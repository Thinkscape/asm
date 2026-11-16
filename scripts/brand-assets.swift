// Renders the app icon and the README images from the square icon artwork.
//
//   swift scripts/brand-assets.swift docs/assets/src/appicon.png
//
// The argument is the full-bleed square icon artwork (the squircle touching the edges,
// e.g. 1254²); the tracked source is docs/assets/src/appicon.png. Run from the
// repository root. Writes:
//   app/Bundle/AppIcon.icns          macOS icon grid: 824/1024 artwork, continuous-corner
//                                    mask (radius 185/824), soft drop shadow
//   docs/assets/icon.png             512² of the same icon
//   docs/assets/logotype.png         icon + "ASM" + tagline for light backgrounds
//   docs/assets/logotype-dark.png    the same for dark backgrounds
import AppKit
import SwiftUI

let arguments = CommandLine.arguments
guard arguments.count == 2,
      let source = NSImage(contentsOfFile: arguments[1])?.cgImage(forProposedRect: nil, context: nil, hints: nil)
else {
    FileHandle.standardError.write("usage: swift scripts/brand-assets.swift <artwork.png>\n".data(using: .utf8)!)
    exit(2)
}

let fm = FileManager.default
let root = URL(fileURLWithPath: fm.currentDirectoryPath)

func context(_ size: Int) -> CGContext {
    let ctx = CGContext(
        data: nil, width: size, height: size, bitsPerComponent: 8, bytesPerRow: 0,
        space: CGColorSpace(name: CGColorSpace.sRGB)!,
        bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
    )!
    ctx.interpolationQuality = .high
    return ctx
}

func writePNG(_ image: CGImage, _ url: URL) {
    try! fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
    let dest = CGImageDestinationCreateWithURL(url as CFURL, "public.png" as CFString, 1, nil)!
    CGImageDestinationAddImage(dest, image, nil)
    precondition(CGImageDestinationFinalize(dest), "cannot write \(url.path)")
}

/// The artwork clipped to the icon mask, filling a `size`² canvas. The source is
/// over-scanned by 1% per side so its own anti-aliased edge never shows.
func maskedArtwork(_ size: Int) -> CGImage {
    let ctx = context(size)
    let rect = CGRect(x: 0, y: 0, width: size, height: size)
    let radius = CGFloat(size) * 185 / 824
    ctx.addPath(RoundedRectangle(cornerRadius: radius, style: .continuous).path(in: rect).cgPath)
    ctx.clip()
    ctx.draw(source, in: rect.insetBy(dx: -CGFloat(size) * 0.01, dy: -CGFloat(size) * 0.01))
    return ctx.makeImage()!
}

/// The icon on the macOS grid: artwork 824/1024 of the canvas, centred, with the
/// system-style drop shadow.
func gridIcon(_ size: Int) -> CGImage {
    let s = CGFloat(size) / 1024
    let ctx = context(size)
    let art = maskedArtwork(max(16, Int((824 * s).rounded())))
    let frame = CGRect(x: 100 * s, y: 100 * s, width: 824 * s, height: 824 * s)
    if size >= 32 {
        ctx.setShadow(offset: CGSize(width: 0, height: -10 * s), blur: 20 * s, color: CGColor(gray: 0, alpha: 0.32))
    }
    ctx.draw(art, in: frame)
    return ctx.makeImage()!
}

// AppIcon.iconset → AppIcon.icns
let iconset = fm.temporaryDirectory.appendingPathComponent("AppIcon.iconset")
try? fm.removeItem(at: iconset)
try! fm.createDirectory(at: iconset, withIntermediateDirectories: true)
for points in [16, 32, 128, 256, 512] {
    writePNG(gridIcon(points), iconset.appendingPathComponent("icon_\(points)x\(points).png"))
    writePNG(gridIcon(points * 2), iconset.appendingPathComponent("icon_\(points)x\(points)@2x.png"))
}
let iconutil = Process()
iconutil.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
iconutil.arguments = ["-c", "icns", iconset.path, "-o", root.appendingPathComponent("app/Bundle/AppIcon.icns").path]
try! iconutil.run()
iconutil.waitUntilExit()
precondition(iconutil.terminationStatus == 0, "iconutil failed")
try? fm.removeItem(at: iconset)

writePNG(gridIcon(512), root.appendingPathComponent("docs/assets/icon.png"))

// Logotype: icon, "ASM" in SF Pro Rounded Bold, tagline. Rendered at 2x of 600×150.
struct Logotype: View {
    let artwork: CGImage
    let word: Color
    let tagline: Color

    var body: some View {
        HStack(spacing: 22) {
            Image(decorative: artwork, scale: 1)
                .resizable()
                .interpolation(.high)
                .frame(width: 118, height: 118)
            VStack(alignment: .leading, spacing: -4) {
                Text(verbatim: "ASM")
                    .font(.system(size: 96, weight: .bold, design: .rounded))
                    .foregroundStyle(word)
                Text(verbatim: "Agents Secrets Manager")
                    .font(.system(size: 23, weight: .semibold, design: .rounded))
                    .foregroundStyle(tagline)
                    .padding(.leading, 4)
            }
        }
        .frame(width: 600, height: 150)
    }
}

let logoArtwork = maskedArtwork(512)
let variants: [(file: String, word: Color, tagline: Color)] = [
    ("logotype.png", Color(red: 0x1B / 255, green: 0x25 / 255, blue: 0x59 / 255), Color(red: 0x4F / 255, green: 0x5A / 255, blue: 0x75 / 255)),
    ("logotype-dark.png", Color(red: 0xE9 / 255, green: 0xEC / 255, blue: 0xFF / 255), Color(red: 0xA3 / 255, green: 0xAC / 255, blue: 0xC4 / 255)),
]
MainActor.assumeIsolated {
    for variant in variants {
        let renderer = ImageRenderer(content: Logotype(artwork: logoArtwork, word: variant.word, tagline: variant.tagline))
        renderer.scale = 2
        renderer.isOpaque = false
        writePNG(renderer.cgImage!, root.appendingPathComponent("docs/assets/\(variant.file)"))
    }
}
print("wrote app/Bundle/AppIcon.icns, docs/assets/icon.png, docs/assets/logotype.png, docs/assets/logotype-dark.png")
