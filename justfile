set shell := ["bash", "-euo", "pipefail", "-c"]

identity := env_var_or_default("ASM_CODESIGN_IDENTITY", "Apple Development: abodera@gmail.com (73U2H3E7G9)")
proxy_version := "0.56.0-asm.1"
app := "dist/Agents Secrets Manager.app"

default:
    @just --list

# One-time tool setup for cross-building the CLI
setup:
    cargo install cargo-zigbuild --locked
    rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl

# Patched iron-proxy, universal macOS binary → dist/bin/iron-proxy
proxy:
    mkdir -p dist/bin
    cd third_party/iron-proxy && for arch in arm64 amd64; do \
        GOTOOLCHAIN=go1.27.3 CGO_ENABLED=0 GOOS=darwin GOARCH=$arch go build \
            -ldflags "-s -w -X github.com/ironsh/iron-proxy/internal/version.Version={{proxy_version}}" \
            -o ../../dist/bin/iron-proxy-$arch ./cmd/iron-proxy; \
    done
    lipo -create dist/bin/iron-proxy-arm64 dist/bin/iron-proxy-amd64 -output dist/bin/iron-proxy
    rm dist/bin/iron-proxy-arm64 dist/bin/iron-proxy-amd64

# Rust core → universal static lib, Swift bindings, xcframework
core:
    CFLAGS_aarch64_apple_darwin=-mmacosx-version-min=14.0 cargo build -p asm-core --release --target aarch64-apple-darwin
    CFLAGS_x86_64_apple_darwin=-mmacosx-version-min=14.0 cargo build -p asm-core --release --target x86_64-apple-darwin
    mkdir -p dist/lib
    lipo -create target/aarch64-apple-darwin/release/libasm_core.a target/x86_64-apple-darwin/release/libasm_core.a -output dist/lib/libasm_core.a
    rm -rf app/Sources/AsmCore dist/ffi app/AsmCoreFFI.xcframework
    mkdir -p app/Sources/AsmCore dist/ffi/Headers
    cargo run -q -p uniffi-bindgen-swift -- dist/lib/libasm_core.a app/Sources/AsmCore --swift-sources
    cargo run -q -p uniffi-bindgen-swift -- dist/lib/libasm_core.a dist/ffi/Headers --headers
    cargo run -q -p uniffi-bindgen-swift -- dist/lib/libasm_core.a dist/ffi/Headers --modulemap --module-name asm_coreFFI --modulemap-filename module.modulemap
    xcodebuild -create-xcframework -library dist/lib/libasm_core.a -headers dist/ffi/Headers -output app/AsmCoreFFI.xcframework

# Native libraries asm-core needs at link time (copy into app/Package.swift linkerSettings)
core-native-libs:
    cargo rustc -p asm-core --release --crate-type staticlib -- --print native-static-libs 2>&1 | grep native-static-libs

# macOS app bundle, signed
app: proxy core
    swift build -c release --arch arm64 --arch x86_64 --package-path app
    rm -rf "{{app}}"
    mkdir -p "{{app}}/Contents/MacOS"
    cp "$(swift build -c release --arch arm64 --arch x86_64 --package-path app --show-bin-path)/AsmApp" "{{app}}/Contents/MacOS/AsmApp"
    cp dist/bin/iron-proxy "{{app}}/Contents/MacOS/iron-proxy"
    cp app/Bundle/Info.plist "{{app}}/Contents/Info.plist"
    codesign --force --options runtime --sign "{{identity}}" "{{app}}/Contents/MacOS/iron-proxy"
    codesign --force --options runtime --sign "{{identity}}" "{{app}}"

# CLI for Linux (static musl) and macOS (universal)
cli:
    cargo zigbuild --release -p asm-cli --target x86_64-unknown-linux-musl
    cargo zigbuild --release -p asm-cli --target aarch64-unknown-linux-musl
    cargo zigbuild --release -p asm-cli --target universal2-apple-darwin
    mkdir -p dist/cli
    cp target/x86_64-unknown-linux-musl/release/asm dist/cli/asm-linux-x86_64
    cp target/aarch64-unknown-linux-musl/release/asm dist/cli/asm-linux-aarch64
    cp target/universal2-apple-darwin/release/asm dist/cli/asm-macos-universal

# Install the CLI on this Mac as ~/.local/bin/asm (override with dir=…)
install-cli dir="~/.local/bin": cli
    mkdir -p {{dir}}
    install -m 0755 dist/cli/asm-macos-universal {{dir}}/asm
    @echo "installed {{dir}}/asm"

# Install the CLI on a Linux host over SSH as ~/.local/bin/asm (x86_64 or aarch64 picked from uname -m)
install-cli-remote host: cli
    arch=$(ssh {{host}} uname -m); case "$arch" in x86_64|amd64) f=asm-linux-x86_64;; aarch64|arm64) f=asm-linux-aarch64;; *) echo "unsupported arch $arch"; exit 1;; esac; \
    ssh {{host}} 'mkdir -p ~/.local/bin' && scp -q dist/cli/$f {{host}}:.local/bin/asm && ssh {{host}} 'chmod 0755 ~/.local/bin/asm && ~/.local/bin/asm --version'

skill:
    mkdir -p dist/skill/asm
    cp skill/asm/SKILL.md dist/skill/asm/SKILL.md

dist: app cli skill

test:
    cargo test --workspace
    cd third_party/iron-proxy && GOTOOLCHAIN=go1.27.3 go test -race -count=1 ./internal/transform/... ./internal/proxy/...
