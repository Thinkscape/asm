import AppKit
import SwiftUI

private enum SshTargetPresentation: Identifiable {
    case add
    case edit(SshTargetItem)
    case enroll(SshTargetItem)
    /// The target proved none of its pinned keys; `presented` are the keys it offers now.
    case keyReview(SshTargetItem, presented: [SshHostKeyItem])

    var id: String {
        switch self {
        case .add: "new"
        case let .edit(target): "edit-\(target.id)"
        case let .enroll(target): "enroll-\(target.id)"
        case let .keyReview(target, _): "keys-\(target.id)"
        }
    }
}

private enum SshTargetConfirmation {
    case unenroll(SshTargetItem)
    case remove(SshTargetItem)
}

private extension SshTargetItem {
    /// Enroll is offered (again) unless an enroll or removal is running.
    var canEnroll: Bool {
        switch state {
        case .notEnrolled, .enrolled, .needsReenroll, .failed: true
        case .enrolling, .removing: false
        }
    }

    /// asm may have files on the host.
    var canUnenroll: Bool {
        switch state {
        case .enrolled, .needsReenroll, .failed: true
        case .notEnrolled, .enrolling, .removing: false
        }
    }

    /// The core refuses to forget a target that is still enrolled.
    var canRemove: Bool {
        switch state {
        case .notEnrolled, .failed: true
        case .enrolled, .needsReenroll, .enrolling, .removing: false
        }
    }

    /// The host keys can be reviewed unless an enroll or removal is running.
    var canReviewKeys: Bool {
        state != .enrolling && state != .removing
    }
}

/// Settings → SSH Targets: hosts agents can request SSH access to, enrolled once over the
/// operator's own ssh.
struct SshTargetsPane: View {
    let model: AppModel
    @State private var selection: String?
    @State private var presentation: SshTargetPresentation?
    @State private var confirming: SshTargetConfirmation?
    @State private var enrollingID: String?
    @State private var enrollError: String?
    @State private var error: String?
    /// The target whose host keys are being fetched for review.
    @State private var reviewingID: String?
    /// A review found the pinned keys still valid.
    @State private var reviewNote: String?

    private var selected: SshTargetItem? { model.sshTargets.first { $0.id == selection } }

    var body: some View {
        VStack(spacing: 0) {
            if model.sshTargets.isEmpty {
                EmptyStateLine(text: "No SSH targets yet. Add one with +.")
            } else {
                targetsTable
            }
        }
        .toolbar { toolbarItems }
        .sheet(item: $presentation) { presentation in
            switch presentation {
            case .add:
                SshTargetSheet(model: model, target: nil)
            case let .edit(target):
                SshTargetSheet(model: model, target: target)
            case let .enroll(snapshot):
                SshEnrollReview(
                    model: model,
                    target: snapshot,
                    isCurrent: isCurrent(snapshot),
                    enrolling: enrollingID == snapshot.id,
                    error: enrollError
                ) { enroll(snapshot) }
                .interactiveDismissDisabled(enrollingID != nil)
            case let .keyReview(target, presented):
                keyReviewSheet(target, presented: presented)
            }
        }
        .confirmationDialog(
            confirmationTitle,
            isPresented: Binding(get: { confirming != nil }, set: { if !$0 { confirming = nil } }),
            presenting: confirming
        ) { confirmation in
            switch confirmation {
            case let .unenroll(target):
                Button("Remove from Host", role: .destructive) {
                    Task {
                        error = await model.unenrollSshTarget(target.id)
                        if error != nil { reviewIfKeyChanged(target.id) }
                    }
                }
            case let .remove(target):
                Button("Remove", role: .destructive) {
                    Task { error = await model.removeSshTarget(target.id) }
                }
            }
        } message: { confirmation in
            switch confirmation {
            case let .unenroll(target):
                switch target.activeLeases {
                case 0:
                    Text("Removes asm's files and accounts from the host.")
                case 1:
                    Text("Ends 1 active lease on this target and removes asm's files and accounts from the host.")
                default:
                    Text("Ends \(target.activeLeases) active leases on this target and removes asm's files and accounts from the host.")
                }
            case let .remove(target):
                if target.state == .failed {
                    Text("Agents can no longer request access to it. The host may still trust asm. To remove asm there by hand, run: sudo /usr/lib/asm-ssh/asm-remove")
                } else {
                    Text("Agents can no longer request access to it. asm's files stay on the host if any remain.")
                }
            }
        }
        .errorAlert($error)
        .alert(Text("Host key unchanged"), isPresented: Binding(get: { reviewNote != nil }, set: { if !$0 { reviewNote = nil } })) {
            Button("OK") {}
        } message: {
            Text(verbatim: reviewNote ?? "")
        }
        .onChange(of: model.sshTargetFocus, initial: true) { _, id in
            guard let id else { return }
            selection = id
            model.sshTargetFocus = nil
        }
    }

    private var targetsTable: some View {
        Table(model.sshTargets, selection: $selection) {
            TableColumn("Name") { (target: SshTargetItem) in Text(verbatim: target.name) }
            TableColumn("Destination") { (target: SshTargetItem) in
                Text(verbatim: target.destination).help(Text(verbatim: target.destination))
            }
            TableColumn("Login") { (target: SshTargetItem) in Text(verbatim: target.privilegedLogin) }
            TableColumn("State") { (target: SshTargetItem) in SshTargetStateCell(target: target) }
                .width(min: 140, ideal: 220)
            TableColumn("Leases") { (target: SshTargetItem) in
                Text(verbatim: String(target.activeLeases)).monospacedDigit()
            }
            .width(50)
        }
        .contextMenu(forSelectionType: String.self) { ids in
            if let id = ids.first, let target = model.sshTargets.first(where: { $0.id == id }) {
                Button("Edit…") { presentation = .edit(target) }
                Button("Enroll…") { reviewEnrollment(target) }
                    .disabled(!target.canEnroll || enrollingID != nil)
                Button("Review Host Key…") { reviewHostKey(target) }
                    .disabled(reviewingID != nil || !target.canReviewKeys)
                Button("Remove from Host…", role: .destructive) { confirming = .unenroll(target) }
                    .disabled(!target.canUnenroll)
                Button("Remove…", role: .destructive) { confirming = .remove(target) }
                    .disabled(!target.canRemove)
            }
        } primaryAction: { ids in
            if let id = ids.first, let target = model.sshTargets.first(where: { $0.id == id }) {
                presentation = .edit(target)
            }
        }
    }

    @ToolbarContentBuilder private var toolbarItems: some ToolbarContent {
        ToolbarItemGroup {
            Button { presentation = .add } label: { Label("Add SSH target", systemImage: "plus") }
                .help("Add SSH target")
            Button {
                if let selected { presentation = .edit(selected) }
            } label: {
                Label("Edit", systemImage: "pencil")
            }
            .help("Edit")
            .disabled(selected == nil)
            Button {
                if let selected { reviewEnrollment(selected) }
            } label: {
                Label("Enroll", systemImage: "checkmark.shield")
            }
            .help("Enroll")
            .disabled(!(selected?.canEnroll ?? false) || enrollingID != nil)
            Button {
                if let selected { reviewHostKey(selected) }
            } label: {
                Label("Review Host Key", systemImage: keyChanged ? "key.slash" : "key")
            }
            .help(reviewHelp)
            .disabled(reviewingID != nil || !(selected?.canReviewKeys ?? false))
            Button {
                if let selected { confirming = .unenroll(selected) }
            } label: {
                Label("Remove from Host", systemImage: "eject")
            }
            .help("Remove from Host")
            .disabled(!(selected?.canUnenroll ?? false))
            Button {
                if let selected { confirming = .remove(selected) }
            } label: {
                Label("Remove", systemImage: "minus")
            }
            .help("Remove")
            .disabled(!(selected?.canRemove ?? false))
        }
    }

    private var keyChanged: Bool { selected?.hostKeyChanged ?? false }

    private var reviewHelp: Text {
        keyChanged ? Text("The host key changed: review it")
            : Text("Ask the host for its keys and compare them with the pinned ones")
    }

    private func keyReviewSheet(_ target: SshTargetItem, presented: [SshHostKeyItem]) -> some View {
        let note: Text? = target.state == .notEnrolled ? nil
            : Text("Using them ends this target's active leases. Then enroll it again: if the host was reinstalled, that puts asm back on it.")
        return HostKeyConfirmationView(
            confirmation: .changedKeys(destination: target.destination, expected: target.hostKeys, presented: presented),
            confirmTitle: Text("Use the New Keys"),
            note: note
        ) {
            presentation = nil
        } confirm: {
            presentation = nil
            Task {
                error = await model.replaceSshHostKeys(target.id, expectedRevision: target.revision,
                                                       keys: presented.map(\.line))
            }
        }
    }

    private var confirmationTitle: Text {
        switch confirming {
        case let .unenroll(target)?: Text("Remove asm from “\(Text(verbatim: target.name))”?")
        case let .remove(target)?: Text("Remove SSH target “\(Text(verbatim: target.name))”?")
        case nil: Text(verbatim: "")
        }
    }

    /// The reviewed snapshot is still the target's current revision and can be enrolled.
    private func isCurrent(_ snapshot: SshTargetItem) -> Bool {
        guard let current = model.sshTargets.first(where: { $0.id == snapshot.id }) else { return false }
        return current.revision == snapshot.revision && current.canEnroll
    }

    private func reviewEnrollment(_ target: SshTargetItem) {
        guard target.canEnroll, enrollingID == nil else { return }
        selection = target.id
        enrollError = nil
        presentation = .enroll(target)
    }

    private func enroll(_ snapshot: SshTargetItem) {
        guard isCurrent(snapshot), enrollingID == nil else { return }
        enrollingID = snapshot.id
        enrollError = nil
        Task {
            let failure = await model.enrollSshTarget(snapshot.id, expectedRevision: snapshot.revision)
            enrollingID = nil
            if let failure {
                enrollError = failure
                reviewIfKeyChanged(snapshot.id)
            } else {
                presentation = nil
            }
        }
    }

    /// After a run failed: when the target failed its host key check, show the review
    /// instead of only the error.
    private func reviewIfKeyChanged(_ id: String) {
        guard let target = model.sshTargets.first(where: { $0.id == id }), target.hostKeyChanged else { return }
        error = nil
        reviewHostKey(target)
    }

    /// Asks the host for its keys (no login) and compares them with the pinned ones.
    private func reviewHostKey(_ target: SshTargetItem) {
        guard reviewingID == nil, target.canReviewKeys else { return }
        selection = target.id
        reviewingID = target.id
        Task {
            defer { reviewingID = nil }
            do {
                switch try await model.reviewSshHostKeys(target.id) {
                case .verified:
                    if case .enroll? = presentation { presentation = nil }
                    reviewNote = String(localized: "\(target.name) proved one of its pinned host keys. If a run failed, try it again.")
                case let .keyMismatch(presented):
                    let current = model.sshTargets.first { $0.id == target.id } ?? target
                    presentation = .keyReview(current, presented: presented)
                case let .unreachable(message):
                    error = message
                }
            } catch {
                self.error = error.localizedDescription
            }
        }
    }
}

private struct SshTargetStateCell: View {
    let target: SshTargetItem

    var body: some View {
        HStack(spacing: 4) {
            Image(systemName: icon).foregroundStyle(color)
            Text(verbatim: line).lineLimit(1).truncationMode(.tail)
        }
        .help(Text(verbatim: line))
    }

    private var line: String {
        if target.hostKeyChanged {
            return String(localized: "Host key changed: review it")
        }
        guard let error = target.error, !error.isEmpty else { return target.state.title }
        return "\(target.state.title): \(error)"
    }

    private var icon: String {
        if target.hostKeyChanged { return "key.slash" }
        return switch target.state {
        case .enrolled: "checkmark.circle.fill"
        case .notEnrolled: "circle.dashed"
        case .enrolling, .removing: "arrow.triangle.2.circlepath"
        case .needsReenroll: "exclamationmark.circle.fill"
        case .failed: "exclamationmark.triangle.fill"
        }
    }

    private var color: Color {
        if target.hostKeyChanged { return .red }
        return switch target.state {
        case .enrolled: .green
        case .notEnrolled, .enrolling, .removing: .secondary
        case .needsReenroll: .orange
        case .failed: .red
        }
    }
}

// MARK: - Target sheet

/// Where the sheet's host keys came from.
private enum HostKeySource: Equatable {
    /// The operator's known_hosts.
    case knownHosts
    /// Fetched from the host; the operator confirms them when saving.
    case host
    /// The saved target's pinned keys.
    case saved
}

/// Host keys that need the operator's confirmation before the target is saved.
private enum HostKeyConfirmation: Identifiable {
    /// known_hosts doesn't know the host, so the keys came from the host itself.
    case unknownHost(destination: String, keys: [SshHostKeyItem])
    /// The host proved none of the expected keys and offers `presented` instead.
    case changedKeys(destination: String, expected: [SshHostKeyItem], presented: [SshHostKeyItem])

    var id: String {
        switch self {
        case let .unknownHost(destination, _): "unknown \(destination)"
        case let .changedKeys(destination, _, _): "changed \(destination)"
        }
    }
}

private struct SshTargetSheet: View {
    let model: AppModel
    let target: SshTargetItem?
    @Environment(\.dismiss) private var dismiss

    private enum Field { case name, destination }

    @State private var name = ""
    /// Empty means the host name.
    @State private var destination = ""
    /// Empty means the host name.
    @State private var agentHostname = ""
    @State private var agentPort = 22
    @State private var showAddresses = false
    @State private var privilegedLogin = "root"
    @State private var allowPrivileged = false
    @State private var hostKeys: [SshHostKeyItem] = []
    /// Effective destination that `hostKeys`, `notKnown` and `keysError` describe.
    @State private var keysDestination: String?
    @State private var keySource = HostKeySource.knownHosts
    /// known_hosts has no key for `keysDestination`.
    @State private var notKnown = false
    @State private var keysError: String?
    @State private var looking = false
    /// Bumped by every lookup; only the latest one clears `looking`.
    @State private var lookupID = 0
    @State private var fetching = false
    /// Keys from the host the operator already confirmed.
    @State private var trustedKeys: [String]?
    @State private var logUnits = ""
    @State private var restartUnits = ""
    @State private var maxDuration: UInt64 = 3600
    /// Other users agents may log in as, sorted by name.
    @State private var users: [SshTargetUserItem] = []
    @State private var choosingUsers = false
    /// Agent port last filled in from a host keys lookup; a value typed over it is kept.
    @State private var filledPort: Int?
    @State private var confirmation: HostKeyConfirmation?
    /// How ssh reaches the destination the keys were read for: through these ProxyJump
    /// hops, or through a ProxyCommand.
    @State private var proxyJump: String?
    @State private var proxyCommand = false
    /// The destination the last check couldn't reach; saving without the check is offered.
    @State private var unreachable: String?
    /// The check login before saving is running.
    @State private var checking = false
    @State private var saving = false
    @State private var error: String?
    @State private var loaded = false
    @FocusState private var focus: Field?

    private var trimmedName: String { name.trimmingCharacters(in: .whitespaces) }
    private var trimmedDestination: String { destination.trimmingCharacters(in: .whitespaces) }
    private var trimmedLogin: String { privilegedLogin.trimmingCharacters(in: .whitespaces) }

    /// The destination this Mac's ssh uses: the host name unless set otherwise.
    private var effectiveDestination: String { trimmedDestination.isEmpty ? trimmedName : trimmedDestination }

    /// The host keys state describes the current destination.
    private var keysCurrent: Bool { keysDestination == effectiveDestination }

    /// asm may be on the host, so its name, destination and host keys stay as enrolled.
    private var locked: Bool {
        guard let target else { return false }
        return target.state != .notEnrolled
    }

    /// The host or the login changed, so saving logs in to the host first.
    private var needsHostCheck: Bool {
        guard let target else { return true }
        return effectiveDestination != target.destination
            || hostKeys.map(\.line) != target.hostKeys.map(\.line)
            || trimmedLogin != target.privilegedLogin
    }

    private var saveTitle: String { target == nil ? String(localized: "Add") : String(localized: "Save") }

    private var durations: [LeaseDuration] {
        SshDurations.including(maxDuration, in: SshDurations.maxLease)
    }

    /// Another target that already pins one of these keys; each target needs its own.
    private var keysOwner: SshTargetItem? {
        let lines = Set(hostKeys.map(\.line))
        return model.sshTargets.first { $0.id != target?.id && $0.hostKeys.contains { lines.contains($0.line) } }
    }

    private var problem: String? {
        if checking { return String(localized: "Checking \(effectiveDestination)…") }
        if trimmedName.isEmpty { return String(localized: "Enter a host name.") }
        if !keysCurrent || hostKeys.isEmpty {
            if keysCurrent && notKnown && !fetching { return String(localized: "Get the host keys, or check the host name.") }
            if keysCurrent && keysError != nil { return String(localized: "The host keys couldn't be read.") }
            return String(localized: "Looking up the host keys…")
        }
        if let owner = keysOwner { return String(localized: "SSH target \(owner.name) already has these host keys.") }
        if !(1...65535).contains(agentPort) { return String(localized: "The agent port must be 1–65535.") }
        if trimmedLogin.isEmpty { return String(localized: "Enter the privileged login.") }
        if !allowPrivileged, let admin = users.first(where: { $0.admin != nil }) {
            return String(localized: "\(admin.name) can become root: allow privileged access, or remove it.")
        }
        return nil
    }

    /// After a check couldn't reach the host: save without it (enrollment checks later).
    private var saveWithoutCheck: SheetAction? {
        guard unreachable == effectiveDestination, error != nil else { return nil }
        let title = target == nil ? Text("Add Without Checking") : Text("Save Without Checking")
        return SheetAction(title: title) {
            Task { await saveDraft() }
        }
    }

    private func confirmTitle(_ pending: HostKeyConfirmation) -> Text {
        if case .changedKeys = pending { return Text("Use the New Keys and \(saveTitle)") }
        return Text("Trust and \(saveTitle)")
    }

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Section {
                    TextField("Host name", text: $name, prompt: Text(verbatim: "web.example.com"))
                        .focused($focus, equals: .name)
                        .disabled(locked)
                } footer: {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Agents use this name: asm ssh request web.example.com …, then ssh web.example.com.")
                        if locked {
                            Text("Remove asm from the host to change its name, destination or host keys.")
                        }
                    }
                }
                Section {
                    // A button, not a DisclosureGroup: accessibility and VoiceOver can open it.
                    Button {
                        showAddresses.toggle()
                    } label: {
                        HStack(spacing: 6) {
                            Image(systemName: "chevron.right")
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(.secondary)
                                .rotationEffect(.degrees(showAddresses ? 90 : 0))
                                .accessibilityHidden(true)
                            Text("Different addresses (split DNS)")
                            Spacer(minLength: 0)
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .accessibilityValue(showAddresses ? Text("Expanded") : Text("Collapsed"))
                    .accessibilityHint(Text("Shows the destination this Mac uses and the address agents use"))
                    if showAddresses {
                        TextField(text: $destination, prompt: Text("same as the host name")) {
                            Text("Destination")
                            Text("How this Mac's ssh reaches the host.")
                        }
                        .focused($focus, equals: .destination)
                        .disabled(locked)
                        TextField(text: $agentHostname, prompt: Text("same as the host name")) {
                            Text("Agent hostname")
                            Text("The address agents connect to.")
                        }
                        TextField("Agent port", value: $agentPort, format: .number.grouping(.never))
                    }
                }
                Section {
                    LabeledContent("Host keys") {
                        VStack(alignment: .trailing, spacing: 6) {
                            hostKeysStatus
                        }
                    }
                } footer: {
                    hostKeysFooter
                }
                Section {
                    TextField(text: $privilegedLogin) {
                        Text("Privileged login")
                        Text("asm logs in as this account over your own ssh to enroll and remove. It needs passwordless sudo when it isn't root.")
                    }
                    Toggle(isOn: $allowPrivileged) {
                        Text("Allow privileged access")
                        Text("Agents can then get a shell as the privileged login, through the asm-priv account and sudo. What they change on the host stays after the lease.")
                    }
                } header: {
                    Text("Privileged access")
                }
                Section {
                    if users.isEmpty {
                        Text("None").foregroundStyle(.secondary)
                    }
                    ForEach(users, id: \.name) { user in
                        HStack(spacing: 8) {
                            VStack(alignment: .leading, spacing: 1) {
                                Text(verbatim: user.name)
                                if let why = user.admin {
                                    Text("Can become root (\(Text(verbatim: why)))")
                                        .font(.caption)
                                        .foregroundStyle(.orange)
                                }
                            }
                            Spacer(minLength: 0)
                            Button {
                                users.removeAll { $0.name == user.name }
                            } label: {
                                Image(systemName: "minus.circle")
                            }
                            .buttonStyle(.borderless)
                            .help("Remove \(user.name)")
                            .accessibilityLabel(Text("Remove \(user.name)"))
                        }
                    }
                    Button("Choose Users…") { choosingUsers = true }
                        .disabled(!keysCurrent || hostKeys.isEmpty || trimmedLogin.isEmpty)
                } header: {
                    Text("Other users")
                } footer: {
                    Text("Agents can get a shell as these users, through the asm-priv account and sudo. Choose Users logs in as the privileged login to list the host's accounts. What agents change on the host stays after the lease.")
                }
                Section {
                    TextField("Log units", text: $logUnits, prompt: Text(verbatim: "web.service, worker.service"))
                    TextField("Restart units", text: $restartUnits, prompt: Text(verbatim: "web.service, worker.service"))
                } header: {
                    Text("Restricted access (asm-ops)")
                } footer: {
                    Text("Comma-separated systemd units: agents with restricted access may read the logs of the log units and restart the restart units.")
                }
                Section {
                    Picker("Max lease", selection: $maxDuration) {
                        ForEach(durations) { option in Text(verbatim: option.title).tag(option.id) }
                    }
                } footer: {
                    if target != nil {
                        Text("Saving changes ends this target's active leases. Enroll again to apply them on the host.")
                    }
                }
            }
            .formStyle(.grouped)
            .sheet(isPresented: $choosingUsers) {
                SshUserPicker(
                    model: model, destination: effectiveDestination, login: trimmedLogin,
                    hostKeys: hostKeys.map(\.line), allowPrivileged: allowPrivileged, chosen: users
                ) { chosen in
                    users = chosen
                }
            }
            SheetButtons(saveTitle: target == nil ? "Add" : "Save", problem: problem, error: error,
                         saving: saving || checking, secondary: saveWithoutCheck,
                         cancel: { dismiss() }, save: save)
        }
        .frame(width: 580, height: 680)
        .onAppear(perform: load)
        // A pause in typing looks the destination up in known_hosts; leaving the field does it at once.
        .task(id: effectiveDestination) {
            try? await Task.sleep(for: .milliseconds(700))
            guard !Task.isCancelled else { return }
            await lookUp()
        }
        .onChange(of: focus) { old, _ in
            if old != nil { Task { await lookUp() } }
        }
        .sheet(item: $confirmation) { pending in
            HostKeyConfirmationView(confirmation: pending, confirmTitle: confirmTitle(pending), note: nil) {
                confirmation = nil
            } confirm: {
                confirmation = nil
                switch pending {
                case let .unknownHost(_, keys):
                    trustedKeys = keys.map(\.line)
                case let .changedKeys(_, _, presented):
                    hostKeys = presented
                    keySource = .host
                    trustedKeys = presented.map(\.line)
                }
                Task { await checkThenSave() }
            }
        }
    }

    @ViewBuilder private var hostKeysStatus: some View {
        if effectiveDestination.isEmpty {
            Text("From your known_hosts").foregroundStyle(.secondary)
        } else if looking || fetching {
            HStack(spacing: 6) {
                ProgressView().controlSize(.small)
                (fetching ? Text("Asking the host…") : Text("Looking in your known_hosts…")).foregroundStyle(.secondary)
            }
        } else if keysCurrent, let keysError {
            Text(verbatim: keysError)
                .foregroundStyle(.red)
                .multilineTextAlignment(.trailing)
                .textSelection(.enabled)
            Button("Try Again") { Task { await lookUp(force: true) } }
        } else if keysCurrent, !hostKeys.isEmpty {
            ForEach(hostKeys, id: \.self) { key in
                Text(verbatim: Self.keyLine(key))
                    .font(.caption.monospaced())
                    .textSelection(.enabled)
            }
            if keySource == .host {
                Label("From the host, not your known_hosts", systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
            if let proxyJump {
                Text("Through \(proxyJump), which asm checks against your known_hosts too")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.trailing)
            } else if proxyCommand {
                Text("Through the ProxyCommand in your ssh config")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        } else if keysCurrent, notKnown {
            Label("Not in your known_hosts", systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
            Button("Get Keys from Host") { Task { await fetchKeys() } }
        } else {
            Text("From your known_hosts").foregroundStyle(.secondary)
        }
    }

    @ViewBuilder private var hostKeysFooter: some View {
        if keysCurrent && notKnown && hostKeys.isEmpty {
            Text("Check the host name for typos. If it's right, this Mac hasn't connected to it with ssh, or knows it by another name. Get Keys from Host asks it without logging in; you confirm the keys when you \(saveTitle.lowercased()).")
        } else if keysCurrent && keySource == .host {
            Text("Whoever answered at \(effectiveDestination) sent these keys. You confirm them when you \(saveTitle.lowercased()).")
        } else {
            Text("asm reads the host keys from your own known_hosts and never adds to it. \(saveTitle) logs in as the privileged login to check the host and asm's access.")
        }
    }

    /// `<type> <fingerprint>`.
    fileprivate static func keyLine(_ key: SshHostKeyItem) -> String {
        let type = key.line.split(separator: " ").first.map(String.init) ?? ""
        return "\(type) \(key.fingerprint)"
    }

    /// Comma-separated units, trimmed, empty entries dropped.
    private static func units(_ text: String) -> [String] {
        text.split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    /// Empty when `value` is empty or the host name: the core then uses the host name.
    private func override(_ value: String) -> String {
        let trimmed = value.trimmingCharacters(in: .whitespaces)
        return trimmed == trimmedName ? "" : trimmed
    }

    private func load() {
        guard !loaded else { return }
        loaded = true
        guard let target else { return }
        name = target.name
        destination = target.destination == target.name ? "" : target.destination
        agentHostname = target.agentHostname == target.name ? "" : target.agentHostname
        showAddresses = !destination.isEmpty || !agentHostname.isEmpty
        agentPort = Int(target.agentPort)
        privilegedLogin = target.privilegedLogin
        allowPrivileged = target.allowPrivileged
        hostKeys = target.hostKeys
        keysDestination = target.destination
        keySource = .saved
        logUnits = target.logUnits.joined(separator: ", ")
        restartUnits = target.restartUnits.joined(separator: ", ")
        maxDuration = target.maxDurationSecs
        users = target.users
    }

    /// Reads the current destination's keys from known_hosts, unless the sheet already
    /// knows what known_hosts says about it. Never contacts the host.
    private func lookUp(force: Bool = false) async {
        let requested = effectiveDestination
        guard !locked, !requested.isEmpty else { return }
        lookupID += 1
        let id = lookupID
        if !force, keysDestination == requested, !hostKeys.isEmpty || notKnown || keysError != nil {
            looking = false
            return
        }
        looking = true
        defer { if id == lookupID { looking = false } }
        do {
            let lookup = try await model.lookupSshHostKeys(requested)
            guard requested == effectiveDestination else { return }
            apply(lookup, source: .knownHosts, for: requested)
            notKnown = lookup.keys.isEmpty
        } catch {
            guard requested == effectiveDestination else { return }
            apply(SshHostKeyLookupItem(hostname: requested, port: 22, keys: [], proxyJump: nil, proxyCommand: false),
                  source: .knownHosts, for: requested)
            keysError = error.localizedDescription
        }
    }

    /// Asks the host for its keys without logging in; they still need confirming.
    private func fetchKeys() async {
        let requested = effectiveDestination
        guard !requested.isEmpty, !fetching else { return }
        fetching = true
        defer { fetching = false }
        do {
            let lookup = try await model.fetchSshHostKeys(requested)
            guard requested == effectiveDestination else { return }
            apply(lookup, source: .host, for: requested)
        } catch {
            guard requested == effectiveDestination else { return }
            keysError = error.localizedDescription
        }
    }

    private func apply(_ lookup: SshHostKeyLookupItem, source: HostKeySource, for requested: String) {
        hostKeys = lookup.keys
        keysDestination = requested
        keySource = source
        proxyJump = lookup.proxyJump
        proxyCommand = lookup.proxyCommand
        keysError = nil
        notKnown = false
        if !lookup.keys.isEmpty, (target == nil && agentPort == 22) || agentPort == filledPort {
            agentPort = Int(lookup.port)
            filledPort = Int(lookup.port)
        }
    }

    private func save() {
        guard problem == nil, !saving, !checking else { return }
        error = nil
        unreachable = nil
        guard needsHostCheck else {
            Task { await saveDraft() }
            return
        }
        if keySource == .host, trustedKeys != hostKeys.map(\.line) {
            confirmation = .unknownHost(destination: effectiveDestination, keys: hostKeys)
        } else {
            Task { await checkThenSave() }
        }
    }

    /// Logs in as enrollment will, then saves. A host that proves none of the keys asks
    /// the operator first.
    private func checkThenSave() async {
        let requested = effectiveDestination
        checking = true
        do {
            let result = try await model.checkSshDestination(requested, login: trimmedLogin, hostKeys: hostKeys.map(\.line))
            checking = false
            switch result {
            case .verified:
                await saveDraft()
            case let .keyMismatch(presented):
                confirmation = .changedKeys(destination: requested, expected: hostKeys, presented: presented)
            case let .unreachable(message):
                unreachable = requested
                error = String(localized: "\(message). \(saveTitle) anyway? Enrolling checks the host later.")
            }
        } catch {
            checking = false
            self.error = error.localizedDescription
        }
    }

    private func saveDraft() async {
        saving = true
        let draft = SshTargetDraftItem(
            id: target?.id,
            expectedRevision: target?.revision,
            name: trimmedName,
            destination: override(destination),
            agentHostname: override(agentHostname),
            agentPort: UInt16(agentPort),
            privilegedLogin: trimmedLogin,
            hostKeys: hostKeys.map(\.line),
            allowPrivileged: allowPrivileged,
            logUnits: Self.units(logUnits),
            restartUnits: Self.units(restartUnits),
            users: users,
            maxDurationSecs: maxDuration
        )
        if let failure = await model.saveSshTarget(draft) {
            error = failure
            saving = false
        } else {
            dismiss()
        }
    }
}

/// Lists a host's accounts (logging in as the privileged login) and lets the operator
/// choose the users agents may log in as.
private struct SshUserPicker: View {
    let model: AppModel
    let destination: String
    let login: String
    let hostKeys: [String]
    let allowPrivileged: Bool
    let chosen: [SshTargetUserItem]
    let done: ([SshTargetUserItem]) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var listed: [SshHostUserItem]?
    @State private var selected: Set<String> = []
    @State private var error: String?

    private static let maxUsers = 16

    private var plain: [SshHostUserItem] { (listed ?? []).filter { !$0.system && $0.admin == nil } }
    private var admins: [SshHostUserItem] { (listed ?? []).filter { $0.admin != nil } }
    private var system: [SshHostUserItem] { (listed ?? []).filter { $0.system && $0.admin == nil } }

    var body: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Users on \(Text(verbatim: destination))")
                    .font(.headline)
                    .accessibilityAddTraits(.isHeader)
                Text("Agents can get a shell as the users you choose. asm checks them again when it enrolls the host.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding([.horizontal, .top])
            if listed != nil {
                Form {
                    group(plain, title: Text("Users"), footer: nil)
                    group(admins, title: Text("Can become root"), footer: allowPrivileged
                        ? Text("Access as one of these is the same as privileged access.")
                        : Text("Turn on Allow privileged access to choose these."))
                    group(system, title: Text("System accounts"),
                          footer: Text("Accounts without a login shell get /bin/sh."))
                }
                .formStyle(.grouped)
            } else if let error {
                VStack(spacing: 8) {
                    ErrorLine(message: error)
                    Button("Try Again") { Task { await load() } }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .padding()
            } else {
                ProgressView("Asking \(destination)…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
            HStack {
                if selected.count > Self.maxUsers {
                    Text("Choose at most \(Self.maxUsers) users.").font(.callout).foregroundStyle(.secondary)
                }
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Done", action: finish)
                    .keyboardShortcut(.defaultAction)
                    .disabled(listed == nil || selected.count > Self.maxUsers)
            }
            .padding()
        }
        .frame(width: 460, height: 540)
        .task { await load() }
    }

    @ViewBuilder private func group(_ users: [SshHostUserItem], title: Text, footer: Text?) -> some View {
        if !users.isEmpty {
            Section {
                ForEach(users) { user in
                    Toggle(isOn: Binding(
                        get: { selected.contains(user.name) },
                        set: { on in if on { selected.insert(user.name) } else { selected.remove(user.name) } }
                    )) {
                        Text(verbatim: user.name)
                        Text(Self.detail(user))
                    }
                    .toggleStyle(.checkbox)
                    .disabled(user.admin != nil && !allowPrivileged && !selected.contains(user.name))
                }
            } header: {
                title
            } footer: {
                if let footer { footer }
            }
        }
    }

    /// `uid 1001`, then how it can become root and whether it lacks a login shell.
    private static func detail(_ user: SshHostUserItem) -> String {
        var parts = [String(localized: "uid \(user.uid)")]
        if let why = user.admin { parts.append(String(localized: "can become root (\(why))")) }
        if !user.loginShell { parts.append(String(localized: "no login shell")) }
        return parts.joined(separator: " · ")
    }

    private func load() async {
        error = nil
        do {
            let users = try await model.listSshHostUsers(destination, login: login, hostKeys: hostKeys)
            let names = Set(users.map(\.name))
            selected = Set(chosen.map(\.name)).intersection(names)
            listed = users
        } catch {
            self.error = error.localizedDescription
        }
    }

    private func finish() {
        let byName = Dictionary(uniqueKeysWithValues: (listed ?? []).map { ($0.name, $0) })
        done(selected.sorted().compactMap { name in
            byName[name].map { SshTargetUserItem(name: $0.name, admin: $0.admin) }
        })
        dismiss()
    }
}

/// Asks before a target pins host keys that asm couldn't confirm from known_hosts: keys
/// fetched from the host, or keys that replace ones the host didn't prove.
private struct HostKeyConfirmationView: View {
    let confirmation: HostKeyConfirmation
    let confirmTitle: Text
    /// What confirming changes besides the keys.
    let note: Text?
    let cancel: () -> Void
    let confirm: () -> Void

    private var changed: Bool {
        if case .changedKeys = confirmation { return true }
        return false
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .top, spacing: 14) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.system(size: 30))
                    .foregroundStyle(changed ? .red : .orange)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 6) {
                    title.font(.headline)
                    message.fixedSize(horizontal: false, vertical: true)
                }
            }
            switch confirmation {
            case let .unknownHost(_, keys):
                keyList("The host sent", keys)
            case let .changedKeys(_, expected, presented):
                keyList("Expected", expected)
                keyList("The host sent", presented)
            }
            VStack(alignment: .leading, spacing: 4) {
                Text("Compare a fingerprint with what the host prints on its own console:")
                Text(verbatim: "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub")
                    .font(.callout.monospaced())
                    .textSelection(.enabled)
            }
            .font(.callout)
            .foregroundStyle(.secondary)
            if let note {
                note.font(.callout).fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Spacer()
                Button("Cancel", action: cancel)
                    .keyboardShortcut(.cancelAction)
                Button(role: .destructive, action: confirm) { confirmTitle }
            }
        }
        .padding(20)
        .frame(width: 560)
    }

    private var title: Text {
        switch confirmation {
        case let .unknownHost(destination, _):
            Text("Trust the keys \(destination) sent?")
        case let .changedKeys(destination, _, _):
            Text("The host key of \(destination) has changed")
        }
    }

    private var message: Text {
        switch confirmation {
        case let .unknownHost(destination, _):
            Text("Your known_hosts has no key for \(destination), so these came from whoever answered there. If someone intercepted the connection, asm would pin their keys and send agents to their machine.")
        case let .changedKeys(destination, _, _):
            Text("\(destination) didn't prove any of the expected keys. It may have been reinstalled, or someone may be intercepting the connection (a man-in-the-middle attack). Continue only if you know why its keys changed.")
        }
    }

    private func keyList(_ title: LocalizedStringKey, _ keys: [SshHostKeyItem]) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title).font(.subheadline.weight(.semibold))
            ForEach(keys, id: \.self) { key in
                Text(verbatim: SshTargetSheet.keyLine(key))
                    .font(.caption.monospaced())
                    .textSelection(.enabled)
            }
        }
    }
}

// MARK: - Enroll review

/// What enrolling installs on the target, the script itself, then Enroll.
private struct SshEnrollReview: View {
    let model: AppModel
    let target: SshTargetItem
    let isCurrent: Bool
    let enrolling: Bool
    let error: String?
    let enroll: () -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var showScript = false
    @State private var script: String?
    @State private var scriptError: String?

    private struct InstalledFile: Identifiable {
        let path: String
        let owner: String
        let content: String
        var id: String { path }
    }

    /// "What enrollment changes on a host".
    private var files: [InstalledFile] {
        let tid = target.id
        let tail = "asm managed CA <CA fp> asm-ca-\(tid)"
        let keysOwner = String(localized: "root 0644 in a root-only directory chain")
        var rules = [
            "Defaults:asm-ops !requiretty",
            "asm-ops ALL=(root) NOPASSWD: /usr/lib/asm-ssh/asm-end-lease register *",
            "asm-ops ALL=(root) NOPASSWD: /usr/lib/asm-ssh/asm-end-lease \"\"",
        ]
        rules += target.logUnits.map { "asm-ops ALL=(root) NOPASSWD: /usr/lib/asm-ssh/asm-logs \($0) *" }
        rules += target.restartUnits.map { "asm-ops ALL=(root) NOPASSWD: <systemctl> restart \($0)" }
        // asm-priv runs shells as the privileged login (when allowed) and as each user.
        let runAs = (target.allowPrivileged ? [target.privilegedLogin] : []) + target.users.map(\.name)
        if !runAs.isEmpty {
            rules += [
                "Defaults:asm-priv !requiretty",
                "asm-priv ALL=(root) NOPASSWD: /usr/lib/asm-ssh/asm-end-lease register *",
                "asm-priv ALL=(\(runAs.joined(separator: ", "))) NOPASSWD: ALL",
            ]
        }
        var files = [
            InstalledFile(path: "/usr/lib/asm-ssh/", owner: "root 0755",
                          content: String(localized: "asm-dispatch, asm-shell, asm-end-lease, asm-logs, asm-remove (root 0755 each)")),
            InstalledFile(path: "/var/lib/asm-ssh/manifest", owner: "root 0600",
                          content: String(localized: "tid=, ca=, priv_login=, priv_trust=, port=, ops_uid=, priv_uid=, state=, one user= line per user, and one ops_ak= / priv_ak= line per key file asm may have written")),
            InstalledFile(path: "/run/asm-ssh/", owner: "root 0700",
                          content: String(localized: "lock, sessions/, leases/ and ended: the sessions of asm leases and the leases that ended")),
            InstalledFile(path: "/etc/sudoers.d/asm-ssh", owner: "root 0440",
                          content: String(localized: "checked with visudo -cf, then with sudo -n -l -U <account> per rule:") + "\n"
                              + rules.joined(separator: "\n")),
            InstalledFile(path: "/etc/systemd/system/asm-end-lease.service, .timer", owner: "root 0644",
                          content: String(localized: "runs asm-end-lease --sweep every minute")),
            InstalledFile(path: String(localized: "user asm-ops"), owner: "—",
                          content: String(localized: "system user in its own group only, GECOS “asm managed”, home /var/lib/asm-ops (root 0755), shell asm-dispatch, password *")),
        ]
        if !runAs.isEmpty {
            files.append(InstalledFile(path: String(localized: "user asm-priv"), owner: "—",
                                       content: String(localized: "the same, with home /var/lib/asm-priv and shell asm-shell")))
        }
        files.append(InstalledFile(
            path: String(localized: "asm-ops's first AuthorizedKeysFile (default /var/lib/asm-ops/.ssh/authorized_keys)"),
            owner: keysOwner,
            content: "cert-authority,principals=\"asm-\(tid)-restricted\",restrict <CA> \(tail)\n"
                + "cert-authority,principals=\"asm-\(tid)-cleanup\",restrict,command=\"asm-cleanup\" <CA> \(tail)"
        ))
        if !runAs.isEmpty {
            var lines: [String] = []
            if target.allowPrivileged {
                lines.append("cert-authority,principals=\"asm-\(tid)-privileged\",restrict,pty <CA> \(tail)")
            }
            if !target.users.isEmpty {
                lines.append("cert-authority,principals=\"asm-\(tid)-user\",restrict,pty <CA> \(tail)")
            }
            files.append(InstalledFile(
                path: String(localized: "asm-priv's first AuthorizedKeysFile (default /var/lib/asm-priv/.ssh/authorized_keys)"),
                owner: keysOwner,
                content: lines.joined(separator: "\n")
            ))
        }
        return files
    }

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    Text("Enroll \(Text(verbatim: target.name))?")
                        .font(.title2.weight(.semibold))
                        .accessibilityAddTraits(.isHeader)
                    Text("Runs as \(Text(verbatim: target.privilegedLogin)) on \(Text(verbatim: target.destination)) using your own SSH setup")
                        .fixedSize(horizontal: false, vertical: true)
                    Divider()
                    Text("Installs").font(.headline).accessibilityAddTraits(.isHeader)
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(files) { file in
                            VStack(alignment: .leading, spacing: 2) {
                                Text(verbatim: file.path).font(.callout.monospaced())
                                Text(verbatim: "\(file.owner) · \(file.content)")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            .accessibilityElement(children: .combine)
                        }
                    }
                    .textSelection(.enabled)
                    Text("No existing account or file is changed, and sshd is not reloaded. Enrollment ends with a test login as each asm account.")
                        .font(.callout)
                        .fixedSize(horizontal: false, vertical: true)
                    DisclosureGroup("Show Script", isExpanded: $showScript) {
                        scriptView
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding()
            }
            Divider()
            HStack {
                if enrolling {
                    ProgressView("Enrolling…").controlSize(.small)
                } else if let error {
                    Label(error, systemImage: "exclamationmark.triangle")
                        .font(.callout)
                        .foregroundStyle(.red)
                        .lineLimit(3)
                        .textSelection(.enabled)
                } else if !isCurrent {
                    Label("The target changed. Cancel and review it again.", systemImage: "exclamationmark.triangle")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                    .disabled(enrolling)
                Button("Enroll", action: enroll)
                    .disabled(!isCurrent || enrolling)
            }
            .padding()
        }
        .frame(minWidth: 560, idealWidth: 620, minHeight: 460, idealHeight: 560)
        .task(id: target.revision) { await loadScript() }
    }

    @ViewBuilder private var scriptView: some View {
        if let script {
            ScrollView([.vertical, .horizontal]) {
                Text(verbatim: script)
                    .font(.caption.monospaced())
                    .textSelection(.enabled)
                    .fixedSize()
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(8)
            }
            .frame(height: 280)
            .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 6, style: .continuous))
        } else if let scriptError {
            Text(verbatim: scriptError).foregroundStyle(.red)
        } else {
            ProgressView().controlSize(.small)
        }
    }

    private func loadScript() async {
        do {
            script = try await model.sshEnrollScript(target.id)
            scriptError = nil
        } catch {
            scriptError = error.localizedDescription
        }
    }
}
