import AppKit
import SwiftUI

/// An SSH access request: what each requested host gets (denied, restricted operations,
/// the privileged login or another user) and the lease length. The panel stays
/// unshareable.
struct SshApproval: View {
    let context: RequestContext
    let detail: SshRequestItem
    let model: AppModel

    /// Access per target ID; a target without one is denied.
    @State private var access: [String: SshAccessItem]
    /// Checked restricted operations per target ID.
    @State private var checked: [String: Set<String>]
    @State private var duration: UInt64
    @State private var editingReason = false

    init(context: RequestContext, detail: SshRequestItem, model: AppModel) {
        self.context = context
        self.detail = detail
        self.model = model
        var access: [String: SshAccessItem] = [:]
        var checked: [String: Set<String>] = [:]
        for target in detail.targets where target.ready {
            let available = Self.availableGrants(target, request: detail)
            checked[target.id] = Set(detail.grants).intersection(available)
            if Self.offers(detail.access, on: target, available: available) {
                access[target.id] = detail.access
            }
        }
        _access = State(initialValue: access)
        _checked = State(initialValue: checked)
        _duration = State(initialValue: detail.defaultDurationSecs)
    }

    /// Restricted operations the operator may approve on `target`: what the target allows,
    /// and for a restricted request no more than it asked for.
    private static func availableGrants(_ target: SshApprovalTargetItem, request: SshRequestItem) -> [String] {
        request.access == .restricted ? target.grants.filter(request.grants.contains) : target.grants
    }

    /// The access menu of `target` lists `access`.
    private static func offers(_ access: SshAccessItem, on target: SshApprovalTargetItem, available: [String]) -> Bool {
        switch access {
        case .restricted: !available.isEmpty
        case .privileged: target.allowPrivileged
        case let .user(name): target.users.contains { $0.name == name }
        }
    }

    /// Targets the operator approves, with their access, in request order.
    private var approved: [(target: SshApprovalTargetItem, access: SshAccessItem)] {
        detail.targets.compactMap { target in
            guard target.ready, let access = access[target.id] else { return nil }
            return (target, access)
        }
    }

    /// Checked operations of `target`, in the target's order.
    private func approvedGrants(_ target: SshApprovalTargetItem) -> [String] {
        let checked = checked[target.id] ?? []
        return Self.availableGrants(target, request: detail).filter(checked.contains)
    }

    /// Restricted rows without an operation.
    private var missingOperations: [SshApprovalTargetItem] {
        approved.filter { $0.access == .restricted && approvedGrants($0.target).isEmpty }.map(\.target)
    }

    /// The longest lease every approved target allows.
    private var durationCap: UInt64 {
        approved.map(\.target.maxDurationSecs).filter { $0 > 0 }.min() ?? detail.maxDurationSecs
    }

    private var durations: [LeaseDuration] {
        let cap = durationCap
        return SshDurations.approvalChoices(max: cap, default: min(detail.defaultDurationSecs, cap))
    }

    private var canAllow: Bool {
        context.armed && !model.isResolving(context.request.id) && !approved.isEmpty && missingOperations.isEmpty
    }

    var body: some View {
        let names = Text(verbatim: detail.targets.map(\.name).joined(separator: ", ")).fontWeight(.bold)
        ApprovalScaffold(error: context.error, footnote: nil) {
            ApprovalHeader(
                title: SshRequester.line(context), subtitle: Text("wants SSH access to \(names)"),
                subtitleLineLimit: 2, queue: context.queue
            ) {
                AppIconImage()
            }
        } content: {
            ReasonBlock(reason: detail.reason)
            SshHostTable(
                targets: detail.targets, model: model,
                rootCapable: { target in access[target.id].flatMap { SshRoot.badge($0, on: target) } != nil },
                denied: { target in access[target.id] == nil }
            ) { target in
                accessMenu(target)
            } below: { target in
                if access[target.id] == .restricted {
                    operations(target)
                }
            }
            GetDurationPicker(durations: durations, duration: $duration)
                .onChange(of: durationCap) {
                    if !durations.contains(where: { $0.seconds == duration }) {
                        duration = min(detail.defaultDurationSecs, durationCap)
                    }
                }
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
            footer
        }
    }

    /// The access menu of one row; a target that isn't ready stays denied.
    private func accessMenu(_ target: SshApprovalTargetItem) -> some View {
        let current = target.ready ? access[target.id] : nil
        return SshAccessMenu(
            title: current.map { SshRoot.label($0, on: target) } ?? String(localized: "Denied"),
            rootCapable: current.flatMap { SshRoot.badge($0, on: target) } != nil,
            denied: current == nil,
            accessibilityLabel: String(localized: "Access on \(target.name)")
        ) {
            menuItems(target)
        }
        .disabled(!target.ready)
    }

    /// Denied | Restricted (kinds) | the privileged login | the other users.
    private func menuItems(_ target: SshApprovalTargetItem) -> [PanelMenuItem] {
        let current = access[target.id]
        var items = [PanelMenuItem(title: String(localized: "Denied"), checked: current == nil) {
            access[target.id] = nil
        }]
        let kinds = Self.kinds(Self.availableGrants(target, request: detail))
        if !kinds.isEmpty {
            items.append(PanelMenuItem(
                title: String(localized: "Restricted"), checked: current == .restricted,
                detail: "(\(kinds.joined(separator: ", ")))", startsSection: true
            ) {
                access[target.id] = .restricted
            })
        }
        if target.allowPrivileged {
            items.append(PanelMenuItem(
                title: target.privilegedLogin, checked: current == .privileged,
                badge: SshRoot.badge(.privileged, on: target), startsSection: true
            ) {
                access[target.id] = .privileged
            })
        }
        for (index, user) in target.users.enumerated() {
            items.append(PanelMenuItem(
                title: user.name, checked: current == .user(user.name),
                badge: user.admin.map(SshRoot.badge(admin:)), startsSection: index == 0
            ) {
                access[target.id] = .user(user.name)
            })
        }
        return items
    }

    /// `logs`, `restart`, `reload`, `read`: the kinds of `grants`, in that order.
    private static func kinds(_ grants: [String]) -> [String] {
        ["logs", "restart", "reload", "read"].filter { kind in grants.contains { $0.hasPrefix("\(kind):") } }
    }

    /// The checkboxes of a Restricted row, and an error while none is checked.
    private func operations(_ target: SshApprovalTargetItem) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            ForEach(Self.availableGrants(target, request: detail), id: \.self) { grant in
                Toggle(isOn: grantBinding(grant, of: target)) {
                    SshRequester.grantTitle(grant)
                        .lineLimit(2)
                        .truncationMode(.middle)
                }
                .toggleStyle(.checkbox)
            }
            if approvedGrants(target).isEmpty {
                Label {
                    Text("Choose at least one operation for \(Text(verbatim: target.name))")
                        .fixedSize(horizontal: false, vertical: true)
                } icon: {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.red)
                }
            }
        }
        .font(.system(size: 12))
        .padding(.leading, 16)
        .padding(.bottom, 6)
    }

    private func grantBinding(_ grant: String, of target: SshApprovalTargetItem) -> Binding<Bool> {
        Binding(
            get: { checked[target.id]?.contains(grant) ?? false },
            set: { on in
                if on {
                    checked[target.id, default: []].insert(grant)
                } else {
                    checked[target.id]?.remove(grant)
                }
            }
        )
    }

    /// Root logins, logins that can keep access, and how asm logs in.
    private var footer: some View {
        let roots = approved.filter { SshRoot.badge($0.access, on: $0.target) != nil }.map(\.target.name)
        let logins = approved.contains { $0.access != .restricted }
        let host = Text(verbatim: context.request.hostLabel)
        return VStack(alignment: .leading, spacing: 4) {
            if !roots.isEmpty {
                Label {
                    Text("Root on \(Text(verbatim: roots.formatted(.list(type: .and)))). Changes there can outlast the lease anywhere on the host, including new accounts and keys.")
                        .foregroundStyle(.primary)
                } icon: {
                    SshShield()
                }
            }
            if logins {
                Text("Every login except Restricted can keep access after the lease, for example with its own key or a cron job.")
            }
            Text("Users log in as asm-priv, then sudo switches to them; Restricted logs in as asm-ops. Any process on \(host) can use this access.")
        }
        .font(.caption)
        .foregroundStyle(.secondary)
        .fixedSize(horizontal: false, vertical: true)
    }

    /// `<name>: <login>` per approved target.
    private var logins: String {
        approved.map { "\($0.target.name): \(SshRequester.login($0.target, access: $0.access))" }
            .joined(separator: "\n")
    }

    private func allow() {
        guard canAllow else { return }
        let decisions = approved.map { row in
            SshTargetDecisionItem(
                targetID: row.target.id, access: row.access,
                grants: row.access == .restricted ? approvedGrants(row.target) : []
            )
        }
        context.resolve(.approveSsh(targets: decisions, durationSecs: duration))
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

    private func leaseTarget(_ target: SshApprovalTargetItem) -> SshExtendTargetItem? {
        detail.targets.first { $0.id == target.id }
    }

    var body: some View {
        let targets = detail.targets.map(\.target)
        let names = Text(verbatim: targets.map(\.name).joined(separator: ", ")).fontWeight(.bold)
        ApprovalScaffold(
            error: context.error,
            footnote: Text("Any process on \(Text(verbatim: context.request.hostLabel)) can use this access. The lease keeps its targets, access and grants; only its end moves.")
        ) {
            ApprovalHeader(
                title: SshRequester.line(context), subtitle: Text("wants to extend SSH access to \(names)"),
                subtitleLineLimit: 2, queue: context.queue
            ) {
                AppIconImage()
            }
        } content: {
            ReasonBlock(reason: detail.reason)
            SshHostTable(
                targets: targets, model: model,
                rootCapable: { target in
                    leaseTarget(target).flatMap { SshRoot.badge($0.access, on: target) } != nil
                },
                denied: { _ in false }
            ) { target in
                if let lease = leaseTarget(target) {
                    SshAccessLabel(
                        title: SshRoot.label(lease.access, on: target),
                        rootCapable: SshRoot.badge(lease.access, on: target) != nil,
                        denied: false
                    )
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            } below: { target in
                if let lease = leaseTarget(target), lease.access == .restricted {
                    VStack(alignment: .leading, spacing: 3) {
                        ForEach(lease.grants, id: \.self) { grant in
                            SshRequester.grantTitle(grant)
                                .lineLimit(2)
                                .truncationMode(.middle)
                        }
                    }
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
                    .padding(.leading, 16)
                    .padding(.bottom, 6)
                }
            }
            TimelineView(.periodic(from: .now, by: 30)) { timeline in
                Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 12, verticalSpacing: 4) {
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
            InfoRow(label: "Host keys", value: SshRequester.hostKeys(targets))
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

    /// `Read logs of <unit>`, `Restart <unit>`, `Reload <unit>` or `Read <path>`.
    static func grantTitle(_ grant: String) -> Text {
        if let unit = grant.unit(after: "logs:") {
            return Text("Read logs of \(Text(verbatim: unit))")
        }
        if let unit = grant.unit(after: "restart:") {
            return Text("Restart \(Text(verbatim: unit))")
        }
        if let unit = grant.unit(after: "reload:") {
            return Text("Reload \(Text(verbatim: unit))")
        }
        if let path = grant.unit(after: "read:") {
            return Text("Read \(Text(verbatim: path))")
        }
        return Text(verbatim: grant)
    }
}

/// Which access can become root on a target, and how the popups name an access.
private enum SshRoot {
    /// The closed label of an access: the login or user name, or `Restricted`.
    static func label(_ access: SshAccessItem, on target: SshApprovalTargetItem) -> String {
        switch access {
        case .privileged: target.privilegedLogin
        case .restricted: String(localized: "Restricted")
        case let .user(name): name
        }
    }

    /// How `access` on `target` becomes root, as a badge word; nil when it can't.
    static func badge(_ access: SshAccessItem, on target: SshApprovalTargetItem) -> String? {
        switch access {
        case .restricted: nil
        case .privileged: target.privilegedLogin == "root" ? "superuser" : "sudo"
        case let .user(name): target.users.first { $0.name == name }?.admin.map(badge(admin:))
        }
    }

    /// `uid 0` → `superuser`; `in group sudo|wheel|admin` or `has sudo rules` → `sudo`;
    /// `in group X` → `X`.
    static func badge(admin: String) -> String {
        switch admin {
        case "uid 0": return "superuser"
        case "has sudo rules": return "sudo"
        default:
            guard let group = admin.unit(after: "in group ") else { return admin }
            return ["sudo", "wheel", "admin"].contains(group) ? "sudo" : group
        }
    }
}

/// How the host column shows target names.
private enum SshNames {
    /// An IPv4 address, or an IPv6 one (no DNS labels to split).
    static func isAddress(_ name: String) -> Bool {
        if name.contains(":") { return true }
        let parts = name.split(separator: ".", omittingEmptySubsequences: false)
        return parts.count == 4 && parts.allSatisfy { UInt8($0) != nil }
    }

    /// The longest suffix of at least two whole labels every name ends in, leaving at least
    /// one label before it; nil with fewer than two names or when any is an IP address.
    static func sharedSuffix(_ names: [String]) -> String? {
        guard names.count >= 2, !names.contains(where: isAddress) else { return nil }
        let labels = names.map { $0.split(separator: ".", omittingEmptySubsequences: false).map(String.init) }
        let limit = (labels.map(\.count).min() ?? 0) - 1
        var count = 0
        while count < limit {
            let label = labels[0][labels[0].count - 1 - count].lowercased()
            guard labels.allSatisfy({ $0[$0.count - 1 - count].lowercased() == label }) else { break }
            count += 1
        }
        return count >= 2 ? labels[0].suffix(count).joined(separator: ".") : nil
    }

    /// The first label, and the rest of the name from its dot without the shared suffix;
    /// an IP address stays whole.
    static func parts(_ name: String, suffix: String?) -> (first: String, rest: String?) {
        guard !isAddress(name), let dot = name.firstIndex(of: ".") else { return (name, nil) }
        var rest = String(name[dot...])
        if let suffix, rest.lowercased().hasSuffix(".\(suffix.lowercased())") {
            rest.removeLast(suffix.count + 1)
        }
        return (String(name[..<dot]), rest.isEmpty ? nil : rest)
    }

    /// `host:port` agents connect to, IPv6 in brackets; nil for a removed target.
    static func address(_ target: SshApprovalTargetItem) -> String? {
        guard !target.hostname.isEmpty else { return nil }
        let host = target.hostname.contains(":") ? "[\(target.hostname)]" : target.hostname
        return "\(host):\(target.port)"
    }

    /// The address, when it says more than the name.
    static func extraAddress(_ target: SshApprovalTargetItem) -> String? {
        guard target.hostname != target.name || target.port != 22 else { return nil }
        return address(target)
    }
}

/// The Host and Access table of both SSH approvals: one row per target, a host cell that
/// links to the target, the access cell and what goes under the row.
private struct SshHostTable<Access: View, Below: View>: View {
    let targets: [SshApprovalTargetItem]
    let model: AppModel
    /// The row's access can become root: orange tint and leading bar.
    let rootCapable: (SshApprovalTargetItem) -> Bool
    /// The row is denied: name struck through.
    let denied: (SshApprovalTargetItem) -> Bool
    @ViewBuilder let access: (SshApprovalTargetItem) -> Access
    @ViewBuilder let below: (SshApprovalTargetItem) -> Below

    var body: some View {
        let suffix = SshNames.sharedSuffix(targets.map(\.name))
        VStack(alignment: .leading, spacing: 8) {
            if let suffix {
                Text("All hosts end in \(Text(verbatim: ".\(suffix)").fontWeight(.semibold))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            VStack(alignment: .leading, spacing: 0) {
                SshColumns {
                    Text("Host").frame(maxWidth: .infinity, alignment: .leading)
                    Text("Access").frame(maxWidth: .infinity, alignment: .leading)
                }
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(.secondary)
                .padding(.leading, SshRowMetrics.leading)
                .padding(.bottom, 5)
                Divider()
                ForEach(targets) { target in
                    row(target, suffix: suffix)
                    Divider().opacity(0.6)
                }
            }
        }
    }

    private func row(_ target: SshApprovalTargetItem, suffix: String?) -> some View {
        let root = rootCapable(target)
        return VStack(alignment: .leading, spacing: 0) {
            SshColumns {
                SshHostCell(target: target, suffix: suffix, struck: denied(target), model: model)
                access(target)
            }
            .padding(.vertical, 6)
            below(target)
        }
        .padding(.leading, SshRowMetrics.leading)
        .padding(.trailing, SshRowMetrics.trailing)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background {
            if root {
                Color.orange.opacity(0.08)
            }
        }
        .overlay(alignment: .leading) {
            if root {
                Rectangle().fill(Color.orange).frame(width: 3)
            }
        }
    }
}

private enum SshRowMetrics {
    /// Room for the 3 pt bar of root-capable rows; every row keeps it so names line up.
    static let leading: CGFloat = 8
    static let trailing: CGFloat = 4
}

/// Host 60 %, Access 40 % of the width with a 10 pt gap before Access; both vertically
/// centred in the row.
private struct SshColumns: Layout {
    private static let gap: CGFloat = 10

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let width = proposal.width.flatMap { $0.isFinite ? $0 : nil } ?? 340
        let height = zip(subviews, Self.widths(width))
            .map { $0.sizeThatFits(ProposedViewSize(width: $1, height: nil)).height }
            .max() ?? 0
        return CGSize(width: width, height: height)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var x = bounds.minX
        for (subview, width) in zip(subviews, Self.widths(bounds.width)) {
            subview.place(at: CGPoint(x: x, y: bounds.midY), anchor: .leading,
                          proposal: ProposedViewSize(width: width, height: nil))
            x += width + Self.gap
        }
    }

    private static func widths(_ total: CGFloat) -> [CGFloat] {
        let host = (total * 0.6).rounded()
        return [host, max(0, total - host - gap)]
    }
}

/// The first label as a link to the target in Settings → SSH Targets, the rest of the
/// domain, the address when it says more than the name, and why the target can't be
/// approved now.
private struct SshHostCell: View {
    let target: SshApprovalTargetItem
    let suffix: String?
    let struck: Bool
    let model: AppModel

    var body: some View {
        let parts = SshNames.parts(target.name, suffix: suffix)
        VStack(alignment: .leading, spacing: 1) {
            Button { model.showSshTarget(target.id) } label: {
                Text(verbatim: parts.first)
                    .fontWeight(.medium)
                    .strikethrough(struck)
                    .foregroundStyle(struck ? AnyShapeStyle(.secondary) : AnyShapeStyle(.link))
                    .lineLimit(2)
                    .truncationMode(.middle)
                    .multilineTextAlignment(.leading)
            }
            .buttonStyle(.plain)
            .accessibilityHint(Text("Shows it in Settings → SSH Targets"))
            if let rest = parts.rest {
                Text(verbatim: rest)
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            if let address = SshNames.extraAddress(target) {
                Text(verbatim: address)
                    .font(.system(size: 11))
                    .foregroundStyle(.tertiary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            if !target.ready {
                Text(verbatim: target.issue ?? String(localized: "This target is not ready."))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .help(help)
    }

    private var help: Text {
        guard let address = SshNames.address(target) else { return Text(verbatim: target.name) }
        return Text("\(Text(verbatim: target.name))\nconnects to \(Text(verbatim: address))")
    }
}

/// An access as the popups show it: the orange shield for root-capable access, then the
/// name (secondary when denied).
private struct SshAccessLabel: View {
    let title: String
    let rootCapable: Bool
    let denied: Bool

    var body: some View {
        HStack(spacing: 4) {
            if rootCapable {
                SshShield()
            }
            Text(verbatim: title)
                .lineLimit(1)
                .truncationMode(.tail)
                .foregroundStyle(denied ? .secondary : .primary)
        }
        .font(.system(size: 13))
    }
}

/// The access cell of the approval: drawn by SwiftUI like a pop-up button, under an AppKit
/// hit area that opens the native menu (the non-activating panel takes the first click).
private struct SshAccessMenu: View {
    let title: String
    let rootCapable: Bool
    let denied: Bool
    let accessibilityLabel: String
    let items: () -> [PanelMenuItem]
    @Environment(\.isEnabled) private var isEnabled

    var body: some View {
        HStack(spacing: 3) {
            SshAccessLabel(title: title, rootCapable: rootCapable, denied: denied)
            Spacer(minLength: 0)
            Image(systemName: "chevron.up.chevron.down")
                .font(.system(size: 9, weight: .semibold))
                .foregroundStyle(.secondary)
        }
        .padding(.leading, 8)
        .padding(.trailing, 6)
        .padding(.vertical, 3)
        .frame(maxWidth: .infinity)
        .background {
            RoundedRectangle(cornerRadius: 6, style: .continuous)
                .fill(Color(nsColor: .controlBackgroundColor))
                .shadow(color: .black.opacity(0.25), radius: 0.75, y: 0.5)
        }
        .overlay {
            RoundedRectangle(cornerRadius: 6, style: .continuous)
                .strokeBorder(rootCapable ? Color.orange.opacity(0.55) : Color.primary.opacity(0.08),
                              lineWidth: rootCapable ? 1 : 0.5)
        }
        .opacity(isEnabled ? 1 : 0.6)
        .accessibilityHidden(true)
        .overlay(PanelMenuHitArea(label: "\(accessibilityLabel): \(title)", items: items))
    }
}

/// The orange shield of root-capable access.
private struct SshShield: View {
    var body: some View {
        Image(systemName: "exclamationmark.shield.fill")
            .foregroundStyle(.orange)
            .accessibilityLabel(Text("can become root"))
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
