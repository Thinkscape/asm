import SwiftUI

/// Root of the approval panel: the shown request, "k of N", and the 1-second guard
/// that ignores approve clicks and Return right after the shown request changes.
struct ApprovalRoot: View {
    let model: AppModel
    @State private var armed = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if let request = model.shownRequest {
                ApprovalHeader(
                    kind: request.kind,
                    hostLabel: request.hostLabel,
                    hostname: request.hostname,
                    agent: request.agent,
                    createdAt: request.createdAt,
                    expiresAt: request.expiresAt,
                    position: (model.pending.firstIndex { $0.id == request.id } ?? 0) + 1,
                    total: model.pending.count,
                    step: model.showNext(offset:)
                )
                ApprovalBody(model: model, request: request, armed: armed)
                    .id(request.id)
            } else {
                Text("No pending requests.")
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, minHeight: 120)
            }
        }
        .padding(.horizontal, 18)
        .padding(.top, 30)
        .padding(.bottom, 16)
        .frame(width: 520)
        .fixedSize(horizontal: false, vertical: true)
        .task(id: model.shownRequestID) {
            armed = false
            try? await Task.sleep(for: .seconds(1))
            armed = !Task.isCancelled
        }
    }
}

private struct ApprovalHeader: View {
    let kind: RequestKind
    /// Friendly name of the host; `hostname` is shown beside it when it differs.
    let hostLabel: String
    let hostname: String
    let agent: String
    let createdAt: Date
    let expiresAt: Date
    let position: Int
    let total: Int
    let step: (Int) -> Void

    private var title: LocalizedStringKey {
        switch kind {
        case .pair: "Pairing request"
        case .get: "Secret request"
        case .update: "Update request"
        case .add: "Add request"
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Label(title, systemImage: kind.symbol).font(.headline)
                Spacer()
                if total > 1 {
                    Button { step(-1) } label: { Image(systemName: "chevron.left") }
                        .buttonStyle(.borderless)
                }
                Text("\(position) of \(total)").font(.callout).monospacedDigit().foregroundStyle(.secondary)
                if total > 1 {
                    Button { step(1) } label: { Image(systemName: "chevron.right") }
                        .buttonStyle(.borderless)
                }
            }
            HStack(spacing: 4) {
                Text(verbatim: hostLabel).fontWeight(.medium)
                if !hostname.isEmpty && hostname != hostLabel {
                    Text(verbatim: "(\(hostname))").foregroundStyle(.secondary)
                }
                if !agent.isEmpty {
                    Text("·").foregroundStyle(.secondary)
                    Text(verbatim: agent).foregroundStyle(.secondary)
                }
                Spacer()
                Text("expires \(expiresAt, style: .relative)").font(.caption).foregroundStyle(.secondary)
            }
            .font(.callout)
            .lineLimit(1)
        }
        .padding(.bottom, 10)
    }
}

private struct ApprovalBody: View {
    let model: AppModel
    let request: PendingItem
    let armed: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            switch request.detail {
            case let .pair(info, address, code):
                PairApproval(info: info, observedAddress: address, code: code, armed: armed) { decision in
                    resolve(decision)
                }
            case let .get(detail):
                GetApproval(
                    detail: detail,
                    durations: CoreBridge.leaseDurations,
                    armed: armed,
                    check: model.checkHostPattern
                ) { decision in
                    resolve(decision)
                }
            case let .update(name, vaultID, vault, field, oldValue, newValue):
                UpdateApproval(name: name, vaultID: vaultID, vaultName: vault, field: field, oldValue: oldValue, newValue: newValue, armed: armed) { decision in
                    resolve(decision)
                }
            case let .add(name, value, targets):
                AddApproval(name: name, value: value, targets: targets, armed: armed) { decision in
                    resolve(decision)
                }
            }
            if let error = request.error ?? model.resolveError {
                Label {
                    Text(verbatim: error)
                } icon: {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.red)
                }
                .font(.callout)
            }
        }
    }

    private func resolve(_ decision: DecisionItem) {
        let id = request.id
        Task { await model.resolve(id, decision) }
    }
}

// MARK: - Shared pieces

/// Deny split button plus the custom-reason editor, followed by the approve buttons.
private struct ApprovalActions<Approve: View>: View {
    let cannedReasons: [String]
    let deny: (String) -> Void
    @ViewBuilder let approve: () -> Approve
    @State private var customReason: String?
    @FocusState private var reasonFocused: Bool

    var body: some View {
        VStack(alignment: .trailing, spacing: 8) {
            if customReason != nil {
                TextField("Reason sent to the agent", text: Binding(
                    get: { customReason ?? "" },
                    set: { customReason = $0 }
                ))
                .textFieldStyle(.roundedBorder)
                .focused($reasonFocused)
                .onSubmit(sendCustom)
                .onAppear { reasonFocused = true }
                HStack {
                    Button("Cancel") { customReason = nil }
                    Button("Deny with this reason", action: sendCustom)
                        .disabled((customReason ?? "").trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
            HStack {
                Menu {
                    ForEach(cannedReasons, id: \.self) { reason in
                        Button("Deny (\(reason))") { deny(reason) }
                    }
                    Button("Deny with custom reason…") { customReason = "" }
                } label: {
                    Text("Deny")
                } primaryAction: {
                    deny("")
                }
                .fixedSize()
                Spacer()
                approve()
            }
        }
        .padding(.top, 4)
    }

    private func sendCustom() {
        let reason = (customReason ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        guard !reason.isEmpty else { return }
        deny(reason)
    }
}

private struct InfoRow: View {
    let label: LocalizedStringKey
    let value: String

    var body: some View {
        GridRow {
            Text(label).foregroundStyle(.secondary).gridColumnAlignment(.trailing)
            Text(verbatim: value).textSelection(.enabled)
        }
    }
}

/// A secret value shown as bullets with its length until revealed.
private struct MaskedValue: View {
    let value: String

    var body: some View {
        Text("\(String(repeating: "•", count: min(value.count, 16))) (\(value.count) characters)")
            .monospaced()
    }
}

// MARK: - Pair

private struct PairApproval: View {
    let info: HostInfoItem
    let observedAddress: String
    let code: String
    let armed: Bool
    let resolve: (DecisionItem) -> Void
    @State private var name: String
    @FocusState private var nameFocused: Bool

    init(info: HostInfoItem, observedAddress: String, code: String, armed: Bool, resolve: @escaping (DecisionItem) -> Void) {
        self.info = info
        self.observedAddress = observedAddress
        self.code = code
        self.armed = armed
        self.resolve = resolve
        _name = State(initialValue: info.hostname)
    }

    /// Same rules as the core (`invalid` there keeps the request pending): at most 64
    /// characters, no control or bidi characters; empty = the hostname.
    private var nameProblem: String? {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.unicodeScalars.contains(where: { $0.properties.generalCategory == .control || (0x202A...0x202E).contains($0.value) || (0x2066...0x2069).contains($0.value) }) {
            return "The name contains a control or text-direction character."
        }
        if trimmed.unicodeScalars.count > 64 {
            return "The name can have at most 64 characters."
        }
        return nil
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Friendly name").font(.caption).foregroundStyle(.secondary)
            TextField(text: $name, prompt: Text(verbatim: info.hostname)) {
                Text("Friendly name")
            }
            .labelsHidden()
            .textFieldStyle(.roundedBorder)
            .focused($nameFocused)
            .onSubmit(approve)
            if let nameProblem {
                Text(verbatim: nameProblem).font(.caption).foregroundStyle(.red)
            }
        }
        .onAppear {
            if NSApp.keyWindow is ApprovalPanel { focusName() }
        }
        .onReceive(NotificationCenter.default.publisher(for: NSWindow.didBecomeKeyNotification)) { note in
            if note.object is ApprovalPanel { focusName() }
        }
        Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 4) {
            InfoRow(label: "Hostname", value: info.hostname)
            InfoRow(label: "User", value: info.username)
            InfoRow(label: "OS", value: "\(info.os) \(info.osVersion)")
            InfoRow(label: "Kernel", value: info.kernel)
            InfoRow(label: "Architecture", value: info.arch)
            InfoRow(label: "Addresses", value: info.addresses.joined(separator: ", "))
            InfoRow(label: "Container", value: info.container ? "yes" : "no")
            InfoRow(label: "asm version", value: info.asmVersion)
            InfoRow(label: "Connected from", value: observedAddress)
        }
        .font(.callout)
        VStack(spacing: 4) {
            Text("Verification code").font(.caption).foregroundStyle(.secondary)
            Text(verbatim: code)
                .font(.system(size: 34, weight: .semibold, design: .monospaced))
                .textSelection(.enabled)
            Text("Approve only if the terminal shows the same code.").font(.caption).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 8)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 8))
        ApprovalActions(cannedReasons: [], deny: { resolve(.deny(reason: $0)) }) {
            // While the name field has focus, Return goes to its `onSubmit` only (one approval).
            Button("Approve", action: approve)
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(nameFocused ? nil : .defaultAction)
                .disabled(!armed || nameProblem != nil)
        }
    }

    private func approve() {
        guard armed, nameProblem == nil else { return }
        resolve(.approvePair(name: name))
    }

    /// Focus the name field and select its text, so typing replaces the hostname.
    private func focusName() {
        nameFocused = true
        DispatchQueue.main.async {
            guard NSApp.keyWindow is ApprovalPanel else { return }
            NSApp.sendAction(#selector(NSText.selectAll(_:)), to: nil, from: nil)
        }
    }
}

// MARK: - Get

private struct HostEntry: Identifiable, Equatable {
    var pattern: String
    var broad: Bool
    var id: String { pattern }
}

private struct GetApproval: View {
    let detail: GetDetail
    let durations: [LeaseDuration]
    let armed: Bool
    let check: (String) -> Result<HostPatternCheckItem, AppError>
    let resolve: (DecisionItem) -> Void

    @State private var hosts: [HostEntry] = []
    @State private var anyHost = false
    @State private var duration: UInt64 = 0
    @State private var loaded = false
    @State private var newHost = ""
    @State private var hostError: String?
    @FocusState private var hostFieldFocused: Bool

    private var suggestions: [String] {
        let present = Set(hosts.map(\.pattern))
        var seen = Set<String>()
        let candidates = detail.requestedHosts + detail.suggestedHosts.map(\.normalized)
        return candidates.filter { !present.contains($0) && seen.insert($0).inserted }
    }

    var body: some View {
        Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 4) {
            InfoRow(label: "Secret", value: detail.name)
            InfoRow(label: "Vault", value: detail.vaultName)
            InfoRow(label: "Fields", value: detail.fields.joined(separator: ", "))
        }
        .font(.callout)

        VStack(alignment: .leading, spacing: 4) {
            Text("Reason").font(.caption).foregroundStyle(.secondary)
            Text(verbatim: detail.reason)
                .font(.title3)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(10)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 8))

        RequestedMode(raw: detail.rawRequested)

        VStack(alignment: .leading, spacing: 6) {
            Text("Allowed hosts").font(.headline)
            if !anyHost {
                ForEach(hosts) { entry in
                    HostEntryRow(pattern: entry.pattern, broad: entry.broad) {
                        hosts.removeAll { $0.pattern == entry.pattern }
                    }
                }
                HStack {
                    TextField("api.example.com or *.example.com", text: $newHost)
                        .textFieldStyle(.roundedBorder)
                        .focused($hostFieldFocused)
                        .onSubmit(addTypedHost)
                    Button("Add", action: addTypedHost).disabled(newHost.trimmingCharacters(in: .whitespaces).isEmpty)
                }
                if let hostError {
                    Text(verbatim: hostError).font(.caption).foregroundStyle(.red)
                }
                if !suggestions.isEmpty {
                    SuggestionChips(suggestions: suggestions, add: add)
                }
            }
            Toggle("Any host", isOn: $anyHost)
            if anyHost {
                Label("Any host lets the agent obtain the real value.", systemImage: "exclamationmark.triangle.fill")
                    .font(.callout)
                    .foregroundStyle(.orange)
            }
        }

        Picker("Duration", selection: $duration) {
            ForEach(durations) { option in
                Text(option.title).tag(option.id)
            }
        }
        .fixedSize()

        ApprovalActions(
            cannedReasons: ["host selection too open", "provide a better reason"],
            deny: { resolve(.deny(reason: $0)) }
        ) {
            Button("Approve and show raw value") {
                resolve(.approveGet(raw: true, durationSecs: durationSecs, hosts: []))
            }
            .disabled(!armed)
            Button("Approve and hide value") {
                resolve(.approveGet(raw: false, durationSecs: durationSecs, hosts: anyHost ? ["*"] : hosts.map(\.pattern)))
            }
            .keyboardShortcut(hostFieldFocused ? nil : .defaultAction)
            .disabled(!armed || (!anyHost && hosts.isEmpty))
        }
        .onAppear(perform: load)
    }

    private var durationSecs: UInt64? { duration == 0 ? nil : duration }

    private func load() {
        guard !loaded else { return }
        loaded = true
        duration = detail.defaultDurationSecs ?? 0
        hosts = detail.initialHosts.map { HostEntry(pattern: $0.normalized, broad: $0.broad) }
    }

    private func add(_ pattern: String) {
        switch check(pattern) {
        case let .success(result):
            hostError = nil
            if result.normalized == "*" {
                anyHost = true
            } else if !hosts.contains(where: { $0.pattern == result.normalized }) {
                hosts.append(HostEntry(pattern: result.normalized, broad: result.broad))
            }
        case let .failure(error):
            hostError = error.message
        }
    }

    private func addTypedHost() {
        let text = newHost.trimmingCharacters(in: .whitespaces)
        guard !text.isEmpty else { return }
        add(text)
        if hostError == nil { newHost = "" }
    }
}

private struct RequestedMode: View {
    let raw: Bool

    var body: some View {
        Label(
            raw ? "The agent asks for the raw value" : "The agent asks for a hidden value (sentinel)",
            systemImage: raw ? "eye.trianglebadge.exclamationmark" : "eye.slash"
        )
        .font(.callout.weight(raw ? .semibold : .regular))
        .foregroundStyle(raw ? .orange : .secondary)
        .padding(raw ? 6 : 0)
        .background(raw ? Color.orange.opacity(0.12) : .clear, in: RoundedRectangle(cornerRadius: 6))
    }
}

private struct HostEntryRow: View {
    let pattern: String
    let broad: Bool
    let remove: () -> Void

    var body: some View {
        HStack {
            Text(verbatim: pattern).monospaced()
            if broad {
                Text("broad")
                    .font(.caption.weight(.semibold))
                    .padding(.horizontal, 5)
                    .background(Color.orange.opacity(0.2), in: Capsule())
                    .foregroundStyle(.orange)
                    .help("This pattern matches many hosts.")
            }
            Spacer()
            Button(action: remove) { Image(systemName: "minus.circle") }
                .buttonStyle(.borderless)
                .help("Remove")
        }
    }
}

private struct SuggestionChips: View {
    let suggestions: [String]
    let add: (String) -> Void

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text("Suggestions").font(.caption).foregroundStyle(.secondary)
            ScrollView(.horizontal, showsIndicators: false) {
                HStack {
                    ForEach(suggestions, id: \.self) { suggestion in
                        Button {
                            add(suggestion)
                        } label: {
                            Text(verbatim: suggestion).font(.caption)
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                    }
                }
            }
        }
    }
}

// MARK: - Update

private struct UpdateApproval: View {
    let name: String
    let vaultID: String
    let vaultName: String
    let field: String
    let oldValue: String
    let newValue: String
    let armed: Bool
    let resolve: (DecisionItem) -> Void
    @State private var revealed = false

    var body: some View {
        Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 6) {
            InfoRow(label: "Secret", value: name)
            InfoRow(label: "Vault", value: vaultName)
            InfoRow(label: "Field", value: field)
            GridRow {
                Text("Old value").foregroundStyle(.secondary).gridColumnAlignment(.trailing)
                if revealed {
                    Text(ChangedRange.highlight(oldValue, against: newValue)).monospaced().textSelection(.enabled)
                } else {
                    MaskedValue(value: oldValue)
                }
            }
            GridRow {
                Text("New value").foregroundStyle(.secondary).gridColumnAlignment(.trailing)
                if revealed {
                    Text(ChangedRange.highlight(newValue, against: oldValue)).monospaced().textSelection(.enabled)
                } else {
                    MaskedValue(value: newValue)
                }
            }
        }
        .font(.callout)
        Toggle("Reveal", isOn: $revealed)
        ApprovalActions(cannedReasons: [], deny: { resolve(.deny(reason: $0)) }) {
            Button("Approve") { resolve(.approveWrite(vaultID: vaultID, collectionID: nil)) }
                .keyboardShortcut(.defaultAction)
                .disabled(!armed)
        }
    }
}

/// Highlights the part of a value that differs from another one: the common
/// prefix and suffix are trimmed, the rest is marked.
enum ChangedRange {
    static func highlight(_ value: String, against other: String) -> AttributedString {
        let a = Array(value), b = Array(other)
        var prefix = 0
        while prefix < a.count, prefix < b.count, a[prefix] == b[prefix] { prefix += 1 }
        var suffix = 0
        while suffix < a.count - prefix, suffix < b.count - prefix, a[a.count - 1 - suffix] == b[b.count - 1 - suffix] { suffix += 1 }
        var result = AttributedString(String(a[..<prefix]))
        var changed = AttributedString(String(a[prefix..<(a.count - suffix)]))
        changed.backgroundColor = .yellow.opacity(0.45)
        changed.foregroundColor = .primary
        result.append(changed)
        result.append(AttributedString(String(a[(a.count - suffix)...])))
        return result
    }
}

// MARK: - Add

private struct AddApproval: View {
    let name: String
    let value: String
    let targets: [AddTargetItem]
    let armed: Bool
    let resolve: (DecisionItem) -> Void

    /// Sentinel tag for "personal vault" in the collection picker.
    private static let personal = "\u{1}personal"

    @State private var revealed = false
    @State private var vaultID = ""
    @State private var collectionID = ""

    private var target: AddTargetItem? { targets.first { $0.vaultID == vaultID } }

    var body: some View {
        Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 6) {
            InfoRow(label: "Name", value: name)
            GridRow {
                Text("Value").foregroundStyle(.secondary).gridColumnAlignment(.trailing)
                if revealed {
                    Text(verbatim: value).monospaced().textSelection(.enabled)
                } else {
                    MaskedValue(value: value)
                }
            }
        }
        .font(.callout)
        Toggle("Reveal", isOn: $revealed)
        if targets.isEmpty {
            Text("No vault can receive this secret.").foregroundStyle(.secondary)
        } else {
            Picker("Vault", selection: $vaultID) {
                ForEach(targets) { target in
                    Text(verbatim: "\(target.vaultName) (\(target.kind.title))").tag(target.vaultID)
                }
            }
            if let target, target.kind == .bitwarden {
                Picker("Collection", selection: $collectionID) {
                    ForEach(target.collections) { collection in
                        Text(verbatim: collection.name).tag(collection.id)
                    }
                    if target.personalAllowed {
                        Text("Personal vault (no organization)").tag(Self.personal)
                    }
                }
            }
        }
        ApprovalActions(cannedReasons: [], deny: { resolve(.deny(reason: $0)) }) {
            Button("Approve") {
                let collection = (target?.kind == .bitwarden && collectionID != Self.personal) ? collectionID : nil
                resolve(.approveWrite(vaultID: vaultID, collectionID: collection))
            }
            .keyboardShortcut(.defaultAction)
            .disabled(!armed || target == nil || (target?.kind == .bitwarden && collectionID.isEmpty))
        }
        .onAppear {
            if vaultID.isEmpty, let first = targets.first { select(first.vaultID) }
        }
        .onChange(of: vaultID) { _, newValue in select(newValue) }
    }

    private func select(_ id: String) {
        vaultID = id
        guard let target = targets.first(where: { $0.vaultID == id }) else { return }
        if target.collections.contains(where: { $0.id == collectionID }) { return }
        collectionID = target.collections.first?.id ?? (target.personalAllowed ? Self.personal : "")
    }
}
