import SwiftUI

/// An SSH access request: which targets, privileged or restricted access, the restricted
/// grants and the lease length. The panel stays unshareable.
struct SshApproval: View {
    let context: RequestContext
    let detail: SshRequestItem
    let model: AppModel

    @State private var selectedTargets: Set<String>
    @State private var access: SshAccessItem
    @State private var grants: Set<String>
    @State private var duration: UInt64
    @State private var editingReason = false

    init(context: RequestContext, detail: SshRequestItem, model: AppModel) {
        self.context = context
        self.detail = detail
        self.model = model
        _selectedTargets = State(initialValue: Set(detail.targets.filter(\.ready).map(\.id)))
        _access = State(initialValue: detail.access)
        _grants = State(initialValue: Set(detail.grants))
        _duration = State(initialValue: detail.defaultDurationSecs)
    }

    /// Checked targets that can be approved now, in request order.
    private var chosen: [SshApprovalTargetItem] {
        detail.targets.filter { $0.ready && selectedTargets.contains($0.id) }
    }

    /// Every chosen target allows privileged access.
    private var privilegedAllowed: Bool {
        !chosen.isEmpty && chosen.allSatisfy(\.allowPrivileged)
    }

    /// Users every chosen target allows, in the first target's order; a user is noted as
    /// able to become root when any chosen target says so.
    private var commonUsers: [SshTargetUserItem] {
        guard let first = chosen.first else { return [] }
        return first.users.compactMap { user in
            let matches = chosen.compactMap { t in t.users.first { $0.name == user.name } }
            guard matches.count == chosen.count else { return nil }
            return SshTargetUserItem(name: user.name, admin: matches.lazy.compactMap(\.admin).first)
        }
    }

    /// Users the access menu lists: every common user, plus the chosen one so the menu
    /// never holds a choice it doesn't show.
    private var userChoices: [SshTargetUserItem] {
        var users = commonUsers
        if case let .user(name) = access, !users.contains(where: { $0.name == name }) {
            users.append(SshTargetUserItem(name: name, admin: nil))
        }
        return users
    }

    /// Units whose logs every chosen target allows reading.
    private var commonLogUnits: [String] {
        guard let first = chosen.first else { return [] }
        return first.logUnits.filter { unit in chosen.allSatisfy { $0.logUnits.contains(unit) } }
    }

    /// Units every chosen target allows restarting.
    private var commonUnits: [String] {
        guard let first = chosen.first else { return [] }
        return first.restartUnits.filter { unit in chosen.allSatisfy { $0.restartUnits.contains(unit) } }
    }

    /// Grants the operator may approve: a restricted request only gets what it asked for.
    private var availableGrants: [String] {
        let all = commonLogUnits.map { "logs:\($0)" } + commonUnits.map { "restart:\($0)" }
        return detail.access == .restricted ? all.filter(detail.grants.contains) : all
    }

    private var approvedGrants: [String] {
        access == .restricted ? availableGrants.filter(grants.contains) : []
    }

    private var durations: [LeaseDuration] {
        SshDurations.approvalChoices(max: detail.maxDurationSecs, default: detail.defaultDurationSecs)
    }

    private var canAllow: Bool {
        guard context.armed, !model.isResolving(context.request.id), !chosen.isEmpty else { return false }
        return switch access {
        case .privileged: privilegedAllowed
        case .restricted: !approvedGrants.isEmpty
        case let .user(name): commonUsers.contains { $0.name == name }
        }
    }

    var body: some View {
        let names = Text(verbatim: detail.targets.map(\.name).joined(separator: ", ")).fontWeight(.bold)
        let host = Text(verbatim: context.request.hostLabel)
        ApprovalScaffold(
            error: context.error,
            footnote: Text("Any process on \(host) can use this access. Ending the lease stops new logins at once; asm then ends its sessions on each target the Mac can reach.")
        ) {
            ApprovalHeader(title: SshRequester.line(context), subtitle: Text("wants SSH access to \(names)"), queue: context.queue) {
                AppIconImage()
            }
        } content: {
            ReasonBlock(reason: detail.reason)
            targetsSection
            accessSection
            if access == .restricted {
                grantsSection
            }
            GetDurationPicker(durations: durations, duration: $duration)
        } details: {
            InfoRow(label: "Requested access", value: detail.access.title)
            InfoRow(label: "Requested grants", value: detail.grants.joined(separator: ", "))
            InfoRow(label: "Logins", value: logins)
            InfoRow(label: "Host keys", value: SshRequester.hostKeys(detail.targets))
            RequestMetaRows(context: context)
        } actions: {
            ApprovalActions(
                cannedReasons: ["access too broad", "provide a better reason"],
                armed: context.armed,
                escapeDenies: true,
                editingReason: $editingReason,
                deny: context.deny
            ) {
                Button("Allow", action: allow)
                    .buttonStyle(.panel)
                    .keyboardShortcut(editingReason ? nil : .defaultAction)
                    .disabled(!canAllow)
            }
        }
    }

    private var targetsSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            SectionLabel("Targets")
            ForEach(detail.targets) { target in
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Toggle(isOn: Binding(
                            get: { target.ready && selectedTargets.contains(target.id) },
                            set: { checked in
                                if checked { selectedTargets.insert(target.id) } else { selectedTargets.remove(target.id) }
                            }
                        )) {
                            Text(verbatim: target.name)
                        }
                        .toggleStyle(.checkbox)
                        .labelsHidden()
                        .disabled(!target.ready)
                        SshTargetLink(target: target, model: model)
                    }
                    SshTargetIssue(target: target)
                }
            }
        }
    }

    /// Privileged access is offered when every chosen target allows it, and stays listed
    /// once picked so the picker never holds a choice it doesn't show.
    private var privilegedOffered: Bool {
        privilegedAllowed || access == .privileged
    }

    private var accessSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 10) {
                SectionLabel("Access")
                if privilegedOffered || !userChoices.isEmpty {
                    Picker("Access", selection: $access) {
                        Text("Restricted").tag(SshAccessItem.restricted)
                        ForEach(userChoices, id: \.name) { user in
                            Text("As \(Text(verbatim: user.name))").tag(SshAccessItem.user(user.name))
                        }
                        if privilegedOffered {
                            Text("Privileged").tag(SshAccessItem.privileged)
                        }
                    }
                    .pickerStyle(.menu)
                    .labelsHidden()
                    .fixedSize()
                } else {
                    Text("Restricted")
                }
                Spacer(minLength: 0)
            }
            accessExplanation
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            accessWarning
        }
    }

    /// What the chosen access risks, or why the chosen targets don't allow it.
    @ViewBuilder private var accessWarning: some View {
        switch access {
        case .restricted:
            EmptyView()
        case .privileged:
            if privilegedAllowed {
                WarningLine(Text("An admin login can keep access after the lease ends, for example by adding its own key."))
            } else {
                let names = chosen.filter { !$0.allowPrivileged }.map(\.name).joined(separator: ", ")
                ErrorLine(message: String(localized: "Privileged access isn't allowed on \(names)."))
            }
        case let .user(name):
            if let user = commonUsers.first(where: { $0.name == name }) {
                if let why = user.admin {
                    WarningLine(Text("\(Text(verbatim: name)) can become root (\(Text(verbatim: why))): this is the same as privileged access."))
                }
                WarningLine(Text("\(Text(verbatim: name)) can keep access after the lease ends, for example by adding its own key or a cron job."))
            } else {
                let names = chosen.filter { t in !t.users.contains { $0.name == name } }.map(\.name).joined(separator: ", ")
                ErrorLine(message: String(localized: "Access as \(name) isn't allowed on \(names)."))
            }
        }
    }

    /// Which account the lease logs in as, and what that account can do.
    private var accessExplanation: Text {
        switch access {
        case .restricted:
            return Text("Logs in as asm-ops, an account asm created on the target that can only run the operations checked below.")
        case .privileged:
            let logins = Set(chosen.map(\.privilegedLogin))
            let login = logins.count == 1 ? Text(verbatim: logins.first!) : Text("each target's privileged login")
            return Text("Logs in as asm-priv, an account asm created on the target, and runs a shell as \(login) through sudo.")
        case let .user(name):
            return Text("Logs in as asm-priv, an account asm created on the target, and runs a shell as \(Text(verbatim: name)) through sudo.")
        }
    }

    private var grantsSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            SectionLabel("Allowed operations")
            if availableGrants.isEmpty {
                Text("The selected targets allow no common operation.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            ForEach(availableGrants, id: \.self) { grant in
                Toggle(isOn: grantBinding(grant)) { Self.grantTitle(grant) }
                    .toggleStyle(.checkbox)
            }
        }
    }

    /// `Read logs of <unit>` or `Restart <unit>`.
    private static func grantTitle(_ grant: String) -> Text {
        if let unit = grant.unit(after: "logs:") {
            return Text("Read logs of \(Text(verbatim: unit))")
        }
        if let unit = grant.unit(after: "restart:") {
            return Text("Restart \(Text(verbatim: unit))")
        }
        return Text(verbatim: grant)
    }

    private func grantBinding(_ grant: String) -> Binding<Bool> {
        Binding(
            get: { grants.contains(grant) },
            set: { checked in
                if checked { grants.insert(grant) } else { grants.remove(grant) }
            }
        )
    }

    private var logins: String {
        chosen.map { "\($0.name): \(SshRequester.login($0, access: access))" }
            .joined(separator: ", ")
    }

    private func allow() {
        guard canAllow else { return }
        context.resolve(.approveSsh(
            targetIDs: chosen.map(\.id), access: access, grants: approvedGrants, durationSecs: duration
        ))
    }
}

/// An agent asks to extend one of its active SSH leases. Targets, access and grants stay
/// as approved; only the end moves.
struct SshExtendApproval: View {
    let context: RequestContext
    let detail: SshExtendRequestItem
    let model: AppModel

    @State private var duration: UInt64
    @State private var editingReason = false

    init(context: RequestContext, detail: SshExtendRequestItem, model: AppModel) {
        self.context = context
        self.detail = detail
        self.model = model
        _duration = State(initialValue: detail.defaultDurationSecs)
    }

    private var durations: [LeaseDuration] {
        SshDurations.approvalChoices(max: detail.maxDurationSecs, default: detail.defaultDurationSecs)
    }

    private var canExtend: Bool {
        context.armed && !model.isResolving(context.request.id) && detail.issue == nil
    }

    /// `Privileged` or `Restricted: <grants>`.
    private var accessLine: String {
        switch detail.access {
        case .privileged: String(localized: "Privileged")
        case .restricted: String(localized: "Restricted: \(detail.grants.joined(separator: ", "))")
        case let .user(name): String(localized: "As \(name)")
        }
    }

    var body: some View {
        let names = Text(verbatim: detail.targets.map(\.name).joined(separator: ", ")).fontWeight(.bold)
        ApprovalScaffold(
            error: context.error,
            footnote: Text("Any process on \(Text(verbatim: context.request.hostLabel)) can use this access. The lease keeps its targets, access and grants; only its end moves.")
        ) {
            ApprovalHeader(title: SshRequester.line(context), subtitle: Text("wants to extend SSH access to \(names)"), queue: context.queue) {
                AppIconImage()
            }
        } content: {
            ReasonBlock(reason: detail.reason)
            VStack(alignment: .leading, spacing: 6) {
                SectionLabel("Targets")
                ForEach(detail.targets) { target in
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 6) {
                            SshTargetLink(target: target, model: model)
                            Text("as \(SshRequester.login(target, access: detail.access))")
                                .foregroundStyle(.secondary)
                        }
                        SshTargetIssue(target: target)
                    }
                }
            }
            TimelineView(.periodic(from: .now, by: 30)) { timeline in
                Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 12, verticalSpacing: 4) {
                    InfoRow(label: "Access", value: accessLine)
                    InfoRow(label: "Ends", value: Self.endLine(detail.expiresAt, now: timeline.date))
                    InfoRow(label: "New end", value: Self.time(timeline.date.addingTimeInterval(TimeInterval(duration))))
                }
            }
            GetDurationPicker(durations: durations, duration: $duration)
            if let issue = detail.issue {
                ErrorLine(message: issue)
            }
        } details: {
            InfoRow(label: "Lease ID", value: detail.leaseID)
            InfoRow(label: "Host keys", value: SshRequester.hostKeys(detail.targets))
            RequestMetaRows(context: context)
        } actions: {
            ApprovalActions(
                cannedReasons: ["provide a better reason"],
                armed: context.armed,
                escapeDenies: true,
                editingReason: $editingReason,
                deny: context.deny
            ) {
                Button("Extend", action: extend)
                    .buttonStyle(.panel)
                    .keyboardShortcut(editingReason ? nil : .defaultAction)
                    .disabled(!canExtend)
            }
        }
    }

    /// `<time>, in <n> min`.
    private static func endLine(_ end: Date, now: Date) -> String {
        let minutes = max(0, Int((end.timeIntervalSince(now) / 60).rounded(.up)))
        return String(localized: "\(time(end)), in \(minutes) min")
    }

    /// The time alone today, with the date otherwise.
    private static func time(_ date: Date) -> String {
        Calendar.current.isDateInToday(date)
            ? date.formatted(date: .omitted, time: .shortened)
            : date.formatted(date: .abbreviated, time: .shortened)
    }

    private func extend() {
        guard canExtend else { return }
        context.resolve(.approveSshExtend(durationSecs: duration))
    }
}

/// What both SSH approvals show about the requester and the targets.
private enum SshRequester {
    /// `<host label> · <agent>`.
    static func line(_ context: RequestContext) -> Text {
        let host = Text(verbatim: context.request.hostLabel)
        return context.request.agent.isEmpty ? host : Text("\(host) · \(Text(verbatim: context.request.agent))")
    }

    /// `<login> via asm-priv` or `asm-ops`.
    static func login(_ target: SshApprovalTargetItem, access: SshAccessItem) -> String {
        switch access {
        case .privileged: "\(target.privilegedLogin) via asm-priv"
        case .restricted: "asm-ops"
        case let .user(name): "\(name) via asm-priv"
        }
    }

    static func hostKeys(_ targets: [SshApprovalTargetItem]) -> String {
        targets.map { "\($0.name): \($0.hostKeyFingerprints.joined(separator: ", "))" }
            .joined(separator: "\n")
    }
}

/// A target's name, linking to it in Settings → SSH Targets, and its address when that
/// says more than the name.
private struct SshTargetLink: View {
    let target: SshApprovalTargetItem
    let model: AppModel

    var body: some View {
        HStack(spacing: 6) {
            Button { model.showSshTarget(target.id) } label: { Text(verbatim: target.name) }
                .buttonStyle(.link)
                .help("Show \(target.name) in Settings → SSH Targets")
            if let address {
                Text(verbatim: address).foregroundStyle(.secondary)
            }
        }
    }

    private var address: String? {
        guard target.hostname != target.name || target.port != 22 else { return nil }
        let host = target.hostname.contains(":") ? "[\(target.hostname)]" : target.hostname
        return "\(host):\(target.port)"
    }
}

/// Why a target can't be approved now; nothing when it is ready.
private struct SshTargetIssue: View {
    let target: SshApprovalTargetItem

    var body: some View {
        if !target.ready {
            Text(verbatim: target.issue ?? String(localized: "This target is not ready."))
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.leading, 20)
        }
    }
}

/// A caption with a warning triangle.
private struct WarningLine: View {
    let text: Text

    init(_ text: Text) {
        self.text = text
    }

    var body: some View {
        Label { text } icon: { Image(systemName: "exclamationmark.triangle.fill") }
            .font(.caption)
            .fixedSize(horizontal: false, vertical: true)
    }
}

private extension String {
    /// The rest of the string after `prefix`, or nil when it doesn't start with it.
    func unit(after prefix: String) -> String? {
        hasPrefix(prefix) ? String(dropFirst(prefix.count)) : nil
    }
}

private extension SshDurations {
    /// Presets up to `max`, plus `default` when it is not one of them.
    static func approvalChoices(max: UInt64, default defaultSecs: UInt64) -> [LeaseDuration] {
        including(defaultSecs, in: approval.filter { ($0.seconds ?? 0) <= max })
    }
}
