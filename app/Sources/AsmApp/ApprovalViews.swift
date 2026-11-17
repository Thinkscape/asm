import AppKit
import SwiftUI

// MARK: - Root

/// Root of the approval panel: the shown request and the 1-second guard that ignores
/// approve clicks, Return and Esc right after the shown request changes.
struct ApprovalRoot: View {
    let model: AppModel
    /// Hides the panel; requests stay pending.
    let close: () -> Void
    @State private var armed = false
    @State private var hovering = false

    var body: some View {
        ApprovalContent(model: model, armed: armed)
            .padding(18)
            .frame(width: 400)
            .fixedSize(horizontal: false, vertical: true)
            .modifier(PanelBackground())
            // Top-aligned, so while the panel animates a height change the content is
            // revealed or hidden at the bottom edge.
            .frame(maxHeight: .infinity, alignment: .top)
            .overlay(alignment: .topLeading) {
                CloseButton(action: close)
                    .padding(6)
                    .opacity(hovering ? 1 : 0)
                    .allowsHitTesting(hovering)
            }
            .onHover { hovering = $0 }
            .task(id: model.shownRequestID) {
                armed = false
                try? await Task.sleep(for: .seconds(1))
                armed = !Task.isCancelled
            }
    }
}

private struct ApprovalContent: View {
    let model: AppModel
    let armed: Bool

    var body: some View {
        if let request = model.shownRequest {
            ApprovalBody(
                model: model,
                request: request,
                queue: QueueInfo(
                    position: (model.pending.firstIndex { $0.id == request.id } ?? 0) + 1,
                    total: model.pending.count,
                    expiresAt: request.expiresAt,
                    step: model.showNext(offset:)
                ),
                armed: armed
            )
            .id(request.id)
        } else {
            Text("No pending requests.")
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, minHeight: 120)
        }
    }
}

/// Liquid Glass on macOS 26 and later, the regular material before.
private struct PanelBackground: ViewModifier {
    func body(content: Content) -> some View {
        let shape = RoundedRectangle(cornerRadius: 24, style: .continuous)
        if #available(macOS 26.0, *) {
            content.glassEffect(.regular, in: shape)
        } else {
            content
                .background(.regularMaterial, in: shape)
                .overlay(shape.strokeBorder(.separator, lineWidth: 0.5))
        }
    }
}

private struct CloseButton: View {
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Image(systemName: "xmark")
                .font(.system(size: 8, weight: .bold))
                .foregroundStyle(.secondary)
                .frame(width: 18, height: 18)
                .background(.regularMaterial, in: Circle())
                .overlay(Circle().strokeBorder(.separator, lineWidth: 0.5))
        }
        .buttonStyle(.plain)
        .help("Close; requests stay pending")
        .accessibilityLabel("Close")
    }
}

/// Position in the queue, navigation and the expiry of the shown request.
private struct QueueInfo {
    var position: Int
    var total: Int
    var expiresAt: Date
    var step: (Int) -> Void
}

/// What every request view needs besides its own detail.
private struct RequestContext {
    var request: PendingItem
    var queue: QueueInfo
    var armed: Bool
    var error: String?
    var resolve: (DecisionItem) -> Void

    func deny(_ reason: String) {
        resolve(.deny(reason: reason))
    }

    /// `<agent> on <host>`, or the host alone when the agent is unknown.
    var requesterTitle: Text {
        request.agent.isEmpty
            ? Text(verbatim: request.hostLabel)
            : Text("\(Text(verbatim: request.agent)) on \(Text(verbatim: request.hostLabel))")
    }

    /// Friendly name, with the reported hostname when it differs.
    var hostLine: String {
        let name = request.hostLabel
        let hostname = request.hostname
        return hostname.isEmpty || hostname == name ? name : "\(name) (\(hostname))"
    }
}

private struct ApprovalBody: View {
    let model: AppModel
    let request: PendingItem
    let queue: QueueInfo
    let armed: Bool

    var body: some View {
        let context = RequestContext(
            request: request,
            queue: queue,
            armed: armed,
            error: request.error ?? model.resolveError,
            resolve: resolve
        )
        switch request.detail {
        case let .pair(info, address, code, repair):
            PairApproval(context: context, info: info, observedAddress: address, code: code, repair: repair)
        case let .get(detail):
            GetApproval(context: context, detail: detail, durations: CoreBridge.leaseDurations, check: model.checkHostPattern)
        case let .update(name, vaultID, vault, field, oldValue, newValue):
            UpdateApproval(
                context: context, name: name, vaultID: vaultID, vaultName: vault,
                field: field, oldValue: oldValue, newValue: newValue
            )
        case let .add(name, value, targets):
            AddApproval(context: context, name: name, value: value, targets: targets)
        }
    }

    private func resolve(_ decision: DecisionItem) {
        let id = request.id
        Task { await model.resolve(id, decision) }
    }
}

// MARK: - Frame

/// Header, request-specific rows, the Details disclosure, the core's error, the
/// action row and a footnote, in that order.
private struct ApprovalScaffold<Header: View, Content: View, Details: View, Actions: View>: View {
    let error: String?
    let footnote: Text?
    let header: Header
    let content: Content
    let details: Details
    let actions: Actions

    init(
        error: String?,
        footnote: Text?,
        @ViewBuilder header: () -> Header,
        @ViewBuilder content: () -> Content,
        @ViewBuilder details: () -> Details,
        @ViewBuilder actions: () -> Actions
    ) {
        self.error = error
        self.footnote = footnote
        self.header = header()
        self.content = content()
        self.details = details()
        self.actions = actions()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            header
            content
            DetailsDisclosure { details }
            if let error {
                ErrorLine(message: error)
            }
            actions
            if let footnote {
                footnote
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

private struct ApprovalHeader<Icon: View>: View {
    let title: Text
    let subtitle: Text
    let queue: QueueInfo
    let icon: Icon

    init(title: Text, subtitle: Text, queue: QueueInfo, @ViewBuilder icon: () -> Icon) {
        self.title = title
        self.subtitle = subtitle
        self.queue = queue
        self.icon = icon()
    }

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            icon
                .frame(width: 40, height: 40)
            VStack(alignment: .leading, spacing: 2) {
                title
                    .font(.system(size: 15, weight: .semibold))
                    .lineLimit(2)
                subtitle
                    .font(.system(size: 13))
                    .lineLimit(4)
            }
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
            QueueBadge(queue: queue)
        }
    }
}

/// The bundle's app icon.
private struct AppIconImage: View {
    var body: some View {
        Image(nsImage: NSApp.applicationIconImage)
            .resizable()
            .interpolation(.high)
            .aspectRatio(contentMode: .fit)
            .accessibilityHidden(true)
    }
}

/// `1 of N` (with arrows when more requests wait) and the time left before the request expires.
private struct QueueBadge: View {
    let queue: QueueInfo

    var body: some View {
        VStack(alignment: .trailing, spacing: 2) {
            HStack(spacing: 2) {
                if queue.total > 1 {
                    Button { queue.step(-1) } label: { Image(systemName: "chevron.left") }
                        .buttonStyle(.borderless)
                        .help("Previous request")
                        .accessibilityLabel("Previous request")
                }
                Text("\(queue.position) of \(queue.total)")
                if queue.total > 1 {
                    Button { queue.step(1) } label: { Image(systemName: "chevron.right") }
                        .buttonStyle(.borderless)
                        .help("Next request")
                        .accessibilityLabel("Next request")
                }
            }
            TimelineView(.periodic(from: .now, by: 1)) { timeline in
                Text("\(Self.remaining(until: queue.expiresAt, now: timeline.date)) left")
            }
        }
        .font(.system(size: 12))
        .monospacedDigit()
        .foregroundStyle(.secondary)
        .fixedSize()
    }

    static func remaining(until end: Date, now: Date) -> String {
        let seconds = max(0, Int(end.timeIntervalSince(now).rounded(.up)))
        return Duration.seconds(seconds).formatted(.time(pattern: seconds >= 3600 ? .hourMinuteSecond : .minuteSecond))
    }
}

/// The agent's reason, quoted, on a tinted background with an accent bar.
private struct ReasonBlock: View {
    let reason: String
    @State private var expanded = false
    @State private var fullHeight: CGFloat = 0
    @State private var shownHeight: CGFloat = 0

    private var quoted: String { "\u{201C}\(reason)\u{201D}" }

    var body: some View {
        HStack(spacing: 0) {
            Rectangle()
                .fill(Color.accentColor)
                .frame(width: 3)
            VStack(alignment: .leading, spacing: 4) {
                Text(verbatim: quoted)
                    .font(.system(size: 14))
                    .lineLimit(expanded ? nil : 4)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .onGeometryChange(for: CGFloat.self) { $0.size.height } action: { shownHeight = $0 }
                    .background(alignment: .topLeading) {
                        // Same text without a line limit, to tell whether the shown one is cut.
                        Text(verbatim: quoted)
                            .font(.system(size: 14))
                            .fixedSize(horizontal: false, vertical: true)
                            .hidden()
                            .onGeometryChange(for: CGFloat.self) { $0.size.height } action: { fullHeight = $0 }
                    }
                if expanded || fullHeight > shownHeight + 1 {
                    Button(expanded ? "Show less" : "Show more") { expanded.toggle() }
                        .buttonStyle(.link)
                        .font(.caption)
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 9)
        }
        .background(Color.accentColor.opacity(0.08))
        .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
        .accessibilityElement(children: .combine)
        .accessibilityLabel(Text("Reason: \(Text(verbatim: reason))"))
    }
}

/// How an approved `get` delivers the secret.
private enum ValueMode: Hashable {
    /// A sentinel that works only through the proxy, over HTTPS, for the approved hosts.
    case proxied
    /// The real value; the agent keeps it.
    case realValue
}

/// Footnote under the action row: what the chosen mode gives the agent.
private struct ValueModeCaption: View {
    let mode: ValueMode

    var body: some View {
        Group {
            switch mode {
            case .proxied:
                Text("The agent gets a token that works only through the proxy, over HTTPS, for the hosts above.")
                    .foregroundStyle(.secondary)
            case .realValue:
                Label {
                    Text("The agent receives the real value and keeps it. It cannot be taken back.")
                } icon: {
                    Image(systemName: "exclamationmark.triangle.fill")
                }
                .foregroundStyle(.orange)
            }
        }
        .font(.system(size: 11))
        .fixedSize(horizontal: false, vertical: true)
    }
}

private struct SectionLabel: View {
    let title: LocalizedStringKey

    init(_ title: LocalizedStringKey) {
        self.title = title
    }

    var body: some View {
        Text(title)
            .font(.system(size: 12, weight: .medium))
            .foregroundStyle(.secondary)
    }
}

/// Collapsed by default; holds label/value rows.
private struct DetailsDisclosure<Rows: View>: View {
    let rows: Rows
    @State private var expanded = false

    init(@ViewBuilder rows: () -> Rows) {
        self.rows = rows()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Divider()
            Button {
                // No `withAnimation`: SwiftUI's animated window resize re-enters AppKit layout
                // and crashes; `ApprovalPanel` animates the height change itself.
                expanded.toggle()
            } label: {
                HStack(spacing: 6) {
                    Image(systemName: "chevron.right")
                        .font(.system(size: 10, weight: .semibold))
                        .rotationEffect(.degrees(expanded ? 90 : 0))
                        .animation(.snappy(duration: 0.2), value: expanded)
                    Text("Details")
                    Spacer()
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .foregroundStyle(.secondary)
            .accessibilityValue(expanded ? Text("expanded") : Text("collapsed"))
            if expanded {
                Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 12, verticalSpacing: 4) {
                    rows
                }
                .font(.system(size: 12))
            }
            Divider()
        }
    }
}

private struct InfoRow: View {
    let label: LocalizedStringKey
    let value: String

    var body: some View {
        GridRow {
            Text(label)
                .foregroundStyle(.secondary)
                .gridColumnAlignment(.leading)
            Text(verbatim: value.isEmpty ? "—" : value)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

/// Rows every request kind shows in Details, after its own.
private struct RequestMetaRows: View {
    let context: RequestContext

    var body: some View {
        InfoRow(label: "Host", value: context.hostLine)
        InfoRow(label: "From", value: context.request.address)
        InfoRow(label: "Agent", value: context.request.agent)
        InfoRow(label: "Created", value: context.request.createdAt.formatted(date: .abbreviated, time: .standard))
        InfoRow(label: "Expires", value: context.request.expiresAt.formatted(date: .abbreviated, time: .standard))
        InfoRow(label: "Request ID", value: context.request.id)
    }
}

private struct ErrorLine: View {
    let message: String

    var body: some View {
        Label {
            Text(verbatim: message).fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.red)
        }
        .font(.callout)
    }
}

/// A secret value shown as bullets with its length until revealed.
private struct MaskedValue: View {
    let value: String

    var body: some View {
        HStack(spacing: 6) {
            Text(verbatim: String(repeating: "•", count: min(value.count, 12))).monospaced()
            Text("\(value.count) characters").foregroundStyle(.secondary)
        }
    }
}

/// Lays children out in rows, wrapping to the proposed width.
private struct FlowLayout: Layout {
    var spacing: CGFloat = 6

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let rows = arrange(width: proposal.width ?? .infinity, subviews: subviews)
        let width = rows.map(\.width).max() ?? 0
        let height = rows.map(\.height).reduce(0, +) + spacing * CGFloat(max(rows.count - 1, 0))
        return CGSize(width: proposal.width ?? width, height: height)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var y = bounds.minY
        for row in arrange(width: bounds.width, subviews: subviews) {
            var x = bounds.minX
            for (index, size) in row.items {
                subviews[index].place(
                    at: CGPoint(x: x, y: y + (row.height - size.height) / 2),
                    proposal: ProposedViewSize(size)
                )
                x += size.width + spacing
            }
            y += row.height + spacing
        }
    }

    private struct Row {
        var items: [(Int, CGSize)] = []
        var width: CGFloat = 0
        var height: CGFloat = 0
    }

    private func arrange(width: CGFloat, subviews: Subviews) -> [Row] {
        var rows: [Row] = []
        var row = Row()
        for index in subviews.indices {
            var size = subviews[index].sizeThatFits(.unspecified)
            if size.width > width {
                size = subviews[index].sizeThatFits(ProposedViewSize(width: width, height: nil))
                size.width = min(size.width, width)
            }
            if !row.items.isEmpty, row.width + spacing + size.width > width {
                rows.append(row)
                row = Row()
            }
            row.width += (row.items.isEmpty ? 0 : spacing) + size.width
            row.height = max(row.height, size.height)
            row.items.append((index, size))
        }
        if !row.items.isEmpty { rows.append(row) }
        return rows
    }
}

// MARK: - Actions

/// Split Deny button (canned reasons, custom reason) on the left, approve buttons on
/// the right. Esc denies without a reason once armed, unless a text field is edited.
private struct ApprovalActions<Trailing: View>: View {
    let cannedReasons: [String]
    let armed: Bool
    let escapeDenies: Bool
    let deny: (String) -> Void
    @Binding var editingReason: Bool
    let trailing: Trailing
    @State private var customReason = ""
    @FocusState private var reasonFocused: Bool

    init(
        cannedReasons: [String],
        armed: Bool,
        escapeDenies: Bool,
        editingReason: Binding<Bool>,
        deny: @escaping (String) -> Void,
        @ViewBuilder trailing: () -> Trailing
    ) {
        self.cannedReasons = cannedReasons
        self.armed = armed
        self.escapeDenies = escapeDenies
        _editingReason = editingReason
        self.deny = deny
        self.trailing = trailing()
    }

    private var trimmedReason: String {
        customReason.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if editingReason {
                HStack(spacing: 6) {
                    TextField("Reason sent to the agent", text: $customReason)
                        .textFieldStyle(.roundedBorder)
                        .focused($reasonFocused)
                        .onSubmit(sendCustom)
                        .onExitCommand { editingReason = false }
                        .onAppear { reasonFocused = true }
                    Button("Cancel") { editingReason = false }
                    Button("Deny", action: sendCustom)
                        .disabled(trimmedReason.isEmpty)
                }
                .controlSize(.regular)
            }
            // One row when it fits (longer translations wrap the approve buttons above Deny).
            ViewThatFits(in: .horizontal) {
                HStack(spacing: 6) {
                    denyButton
                    Spacer(minLength: 0)
                    trailing
                }
                VStack(alignment: .trailing, spacing: 8) {
                    HStack(spacing: 6) { trailing }
                    HStack {
                        denyButton
                        Spacer(minLength: 0)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .trailing)
            }
        }
        .background {
            Button("Deny") { deny("") }
                .keyboardShortcut(.cancelAction)
                .disabled(!armed || !escapeDenies || editingReason)
                .opacity(0)
                .frame(width: 0, height: 0)
                .accessibilityHidden(true)
        }
    }

    private var denyButton: some View {
        DenySplitButton(cannedReasons: cannedReasons, deny: deny) {
            customReason = ""
            editingReason = true
        }
    }

    private func sendCustom() {
        guard !trimmedReason.isEmpty else { return }
        deny(trimmedReason)
    }
}

/// Size shared by the action row's buttons.
private enum PanelButtonMetrics {
    static let height: CGFloat = 40
    static let font = Font.system(size: 15, weight: .medium)
}

/// Deny (no reason) with a menu of reasons. Drawn by SwiftUI like `PanelButtonStyle`,
/// so it looks the same whether or not the non-activating panel is key.
private struct DenySplitButton: View {
    let cannedReasons: [String]
    let deny: (String) -> Void
    let customReason: () -> Void

    var body: some View {
        HStack(spacing: 0) {
            Button {
                deny("")
            } label: {
                Text("Deny")
                    .padding(.leading, 22)
                    .padding(.trailing, 16)
                    .frame(minWidth: 70)
            }
            .buttonStyle(SegmentButtonStyle())
            SegmentDivider(style: AnyShapeStyle(.separator))
            SplitChevron(label: "Deny with a reason") {
                cannedReasons.map { reason in
                    SplitMenuItem(title: "Deny (\(reason))") { deny(reason) }
                } + [SplitMenuItem(title: "Deny with custom reason…", action: customReason)]
            }
        }
        .font(PanelButtonMetrics.font)
        .frame(height: PanelButtonMetrics.height)
        .background(.fill.tertiary, in: Capsule())
        .overlay(Capsule().strokeBorder(.separator, lineWidth: 0.5))
        .clipShape(Capsule())
        .fixedSize()
    }
}

/// Approves a `get`: the primary segment allows in the current mode, the chevron
/// ("Approval mode") only switches the mode. Proxied: accent fill, Return approves.
/// Real value: orange fill, never bound to Return.
private struct AllowSplitButton: View {
    @Binding var mode: ValueMode
    /// The primary segment; the chevron always works.
    let enabled: Bool
    let isDefault: Bool
    let allow: () -> Void

    private var realValue: Bool { mode == .realValue }

    var body: some View {
        let foreground = realValue ? AnyShapeStyle(.black.opacity(0.85)) : AnyShapeStyle(.white)
        HStack(spacing: 0) {
            Button(action: allow) {
                Text(realValue ? "Allow Real Value" : "Allow")
                    .padding(.leading, 22)
                    .padding(.trailing, 16)
                    .frame(minWidth: 96)
            }
            .buttonStyle(SegmentButtonStyle())
            .keyboardShortcut(isDefault ? .defaultAction : nil)
            .disabled(!enabled)
            SegmentDivider(style: realValue ? AnyShapeStyle(.black.opacity(0.25)) : AnyShapeStyle(.white.opacity(0.45)))
            SplitChevron(label: "Approval mode") {
                [
                    SplitMenuItem(title: "Allow through proxy (hidden)", checked: mode == .proxied) {
                        mode = .proxied
                    },
                    SplitMenuItem(title: "Allow real value…", checked: mode == .realValue, tint: .systemOrange) {
                        mode = .realValue
                    },
                ]
            }
            .help("Choose how the agent gets the secret")
        }
        .font(PanelButtonMetrics.font)
        .lineLimit(1)
        .foregroundStyle(foreground)
        .frame(height: PanelButtonMetrics.height)
        .background(
            (realValue ? Color.orange : Color.accentColor).opacity(enabled ? 1 : 0.55),
            in: Capsule()
        )
        .clipShape(Capsule())
        .fixedSize()
    }
}

/// One segment of a split button: full height, darkens while pressed, fades when disabled.
private struct SegmentButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .lineLimit(1)
            .fixedSize()
            .frame(maxHeight: .infinity)
            .background(configuration.isPressed ? Color.black.opacity(0.12) : Color.clear)
            .contentShape(Rectangle())
            .opacity(isEnabled ? 1 : 0.55)
    }
}

private struct SegmentDivider: View {
    let style: AnyShapeStyle

    var body: some View {
        Rectangle()
            .fill(style)
            .frame(width: 1)
            .padding(.vertical, 10)
    }
}

/// One item of a split button's menu.
private struct SplitMenuItem {
    let title: String
    var checked = false
    var tint: NSColor? = nil
    let action: () -> Void
}

/// The menu segment of a split button: a chevron drawn by SwiftUI under an AppKit hit
/// area that fills the whole 44 × 40 pt segment. A SwiftUI `Menu` was used before, but on
/// macOS its clickable control stays the height of the glyph (about 9 pt) whatever frame
/// it is given.
private struct SplitChevron: View {
    let label: String
    let items: () -> [SplitMenuItem]

    var body: some View {
        Image(systemName: "chevron.down")
            .font(.system(size: 13, weight: .semibold))
            .frame(width: 44, height: PanelButtonMetrics.height)
            .accessibilityHidden(true)
            .overlay(SplitMenuHitArea(label: label, items: items))
    }
}

private struct SplitMenuHitArea: NSViewRepresentable {
    let label: String
    let items: () -> [SplitMenuItem]

    func makeNSView(context: Context) -> SplitMenuButton {
        let button = SplitMenuButton()
        button.isBordered = false
        button.title = ""
        button.setButtonType(.momentaryChange)
        update(button)
        return button
    }

    func updateNSView(_ button: SplitMenuButton, context: Context) {
        update(button)
    }

    private func update(_ button: SplitMenuButton) {
        button.items = items
        button.setAccessibilityLabel(label)
        button.setAccessibilityRole(.menuButton)
    }
}

/// Transparent button that opens its menu below itself on click, Space or AX press.
private final class SplitMenuButton: NSButton {
    var items: () -> [SplitMenuItem] = { [] }
    private var actions: [() -> Void] = []

    // The approval panel is non-activating: the first click must work without making it key.
    override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }
    override func mouseDown(with event: NSEvent) { showMenu() }
    override func performClick(_ sender: Any?) { showMenuSoon() }
    // `NSMenu.popUp` runs a modal loop; answer the AX press first, or VoiceOver and other
    // assistive tools wait on it and time out.
    override func accessibilityPerformPress() -> Bool {
        showMenuSoon()
        return true
    }
    private func showMenuSoon() {
        DispatchQueue.main.async { [weak self] in self?.showMenu() }
    }
    override func draw(_ dirtyRect: NSRect) {}

    private func showMenu() {
        let menu = NSMenu()
        menu.autoenablesItems = false
        actions = []
        for (index, spec) in items().enumerated() {
            let item = NSMenuItem(title: spec.title, action: #selector(pick(_:)), keyEquivalent: "")
            item.target = self
            item.tag = index
            item.state = spec.checked ? .on : .off
            if let tint = spec.tint {
                item.attributedTitle = NSAttributedString(
                    string: spec.title,
                    attributes: [.foregroundColor: tint, .font: NSFont.menuFont(ofSize: 0)]
                )
            }
            menu.addItem(item)
            actions.append(spec.action)
        }
        let below = NSPoint(x: 0, y: isFlipped ? bounds.height + 4 : -4)
        menu.popUp(positioning: nil, at: below, in: self)
    }

    @objc private func pick(_ sender: NSMenuItem) {
        guard actions.indices.contains(sender.tag) else { return }
        actions[sender.tag]()
    }
}

/// Filled capsule button drawn by SwiftUI: a new request does not make the panel key,
/// and AppKit buttons would then look inactive (no accent fill, dimmed labels).
private struct PanelButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(PanelButtonMetrics.font)
            .lineLimit(1)
            .padding(.horizontal, 28)
            .fixedSize()
            .frame(minWidth: 120, minHeight: PanelButtonMetrics.height, maxHeight: PanelButtonMetrics.height)
            .foregroundStyle(.white)
            .background(Color.accentColor, in: Capsule())
            .contentShape(Capsule())
            .opacity(isEnabled ? (configuration.isPressed ? 0.75 : 1) : 0.45)
    }
}

extension ButtonStyle where Self == PanelButtonStyle {
    fileprivate static var panel: PanelButtonStyle { PanelButtonStyle() }
}

// MARK: - Pair

private struct PairApproval: View {
    let context: RequestContext
    let info: HostInfoItem
    let observedAddress: String
    let code: String
    /// The machine looks like an already paired host.
    let repair: RepairItem?
    @State private var name: String
    /// `same_machine`: revoke the old pairing and take its name.
    @State private var replace = true
    @State private var editingReason = false
    @FocusState private var nameFocused: Bool

    init(context: RequestContext, info: HostInfoItem, observedAddress: String, code: String, repair: RepairItem?) {
        self.context = context
        self.info = info
        self.observedAddress = observedAddress
        self.code = code
        self.repair = repair
        // Re-pairing or replacing keeps the old host's name.
        _name = State(initialValue: repair?.hostName ?? info.hostname)
    }

    private var sameInstall: Bool { repair?.kind == .sameInstall }

    /// The core ignores the typed name when re-pairing or replacing: the old name stays.
    private var nameKept: Bool {
        guard let repair else { return false }
        return repair.kind == .sameInstall || replace
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

    private var deviceSymbol: String {
        if info.container { return "shippingbox" }
        return info.os.lowercased().contains("linux") ? "server.rack" : "laptopcomputer"
    }

    private var summaryLine: String {
        // `osVersion` often already names the OS ("macOS 27.0.1" for os "macos").
        let os = info.osVersion.lowercased().contains(info.os.lowercased())
            ? info.osVersion
            : [info.os, info.osVersion].filter { !$0.isEmpty }.joined(separator: " ")
        return [info.hostname, os, info.arch, observedAddress].filter { !$0.isEmpty }.joined(separator: " · ")
    }

    private var title: Text {
        if let repair, sameInstall {
            return Text("\(Text(verbatim: repair.hostName)) wants to pair again")
        }
        return Text("New device wants to pair")
    }

    private var subtitle: Text {
        let summary = Text(verbatim: summaryLine).foregroundStyle(.secondary)
        guard sameInstall else { return summary }
        return Text("Same installation as before: keeps its name, leases and history.").foregroundStyle(.secondary)
            + Text(verbatim: "\n") + summary
    }

    var body: some View {
        ApprovalScaffold(
            error: context.error,
            footnote: Text("Pairing lets this device ask for secrets. You still approve every request.")
        ) {
            ApprovalHeader(title: title, subtitle: subtitle, queue: context.queue) {
                Image(systemName: deviceSymbol)
                    .font(.system(size: 28))
                    .foregroundStyle(.secondary)
                    .accessibilityHidden(true)
            }
        } content: {
            if let repair, repair.kind == .sameMachine {
                SameMachineCallout(repair: repair, replace: $replace)
            }
            VStack(alignment: .leading, spacing: 6) {
                SectionLabel("Name")
                TextField(text: $name, prompt: Text(verbatim: info.hostname)) {
                    Text("Name")
                }
                .labelsHidden()
                .textFieldStyle(.roundedBorder)
                .controlSize(.large)
                .focused($nameFocused)
                .onExitCommand { nameFocused = false }
                .disabled(nameKept)
                if nameKept {
                    Text(sameInstall ? "Keeps its current name." : "Takes the old pairing's name.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else if let nameProblem {
                    Text(verbatim: nameProblem).font(.caption).foregroundStyle(.red)
                }
            }
            VStack(spacing: 6) {
                Text(verbatim: code)
                    .font(.system(size: 36, weight: .semibold, design: .monospaced))
                    .monospacedDigit()
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
                    .background(Color.accentColor.opacity(0.1), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                    .accessibilityLabel(Text("Verification code \(Text(verbatim: code))"))
                Text("Must match the code shown in the terminal")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        } details: {
            InfoRow(label: "User", value: info.username)
            InfoRow(label: "Kernel", value: info.kernel)
            InfoRow(label: "Addresses", value: info.addresses.joined(separator: ", "))
            InfoRow(label: "asm version", value: info.asmVersion)
            InfoRow(label: "Container", value: info.container ? String(localized: "yes") : String(localized: "no"))
            InfoRow(label: "Request ID", value: context.request.id)
            if let repair {
                InfoRow(label: "Previous host ID", value: repair.hostID)
            }
        } actions: {
            ApprovalActions(
                cannedReasons: [],
                armed: context.armed,
                escapeDenies: !nameFocused,
                editingReason: $editingReason,
                deny: context.deny
            ) {
                // Not the default button: comparing the codes is the approval, so Return never pairs.
                Button("Pair", action: approve)
                    .buttonStyle(.panel)
                    .disabled(!context.armed || (!nameKept && nameProblem != nil))
            }
        }
        .onAppear {
            if NSApp.keyWindow is ApprovalPanel { focusName() }
        }
        .onChange(of: replace) { _, replacing in
            // Keeps a name the operator typed; swaps only the pre-filled one.
            guard let repair else { return }
            if replacing, name == info.hostname {
                name = repair.hostName
            } else if !replacing, name == repair.hostName {
                name = info.hostname
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: NSWindow.didBecomeKeyNotification)) { note in
            if note.object is ApprovalPanel, !editingReason { focusName() }
        }
    }

    private func approve() {
        guard context.armed, nameKept || nameProblem == nil else { return }
        // `same_install` re-pairs the same record whatever `replace` says.
        context.resolve(.approvePair(name: name, replace: repair != nil && (sameInstall || replace)))
    }

    /// Focus the name field and select its text, so typing replaces the hostname.
    private func focusName() {
        guard !nameKept else { return }
        nameFocused = true
        DispatchQueue.main.async {
            guard NSApp.keyWindow is ApprovalPanel else { return }
            NSApp.sendAction(#selector(NSText.selectAll(_:)), to: nil, from: nil)
        }
    }
}

/// `same_machine` re-pair: which host this looks like and whether to replace it.
private struct SameMachineCallout: View {
    let repair: RepairItem
    @Binding var replace: Bool

    var body: some View {
        let name = Text(verbatim: repair.hostName).fontWeight(.semibold)
        let date = Text(repair.pairedAt, format: .dateTime.year().month().day())
        VStack(alignment: .leading, spacing: 8) {
            Label {
                Text("Looks like \(name) (paired \(date))")
                    .fixedSize(horizontal: false, vertical: true)
            } icon: {
                Image(systemName: "arrow.triangle.2.circlepath").foregroundStyle(Color.accentColor)
            }
            Toggle(isOn: $replace) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Replace \(Text(verbatim: repair.hostName))")
                    Text("Revokes the old pairing and its leases; the new one takes its name.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .toggleStyle(PanelSwitchStyle())
            .accessibilityLabel(Text("Replace \(Text(verbatim: repair.hostName))"))
            .accessibilityHint(Text("Revokes the old pairing and its leases; the new one takes its name."))
        }
        .font(.callout)
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.accentColor.opacity(0.08), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(Color.accentColor.opacity(0.3), lineWidth: 0.5))
    }
}

/// On/off switch drawn by SwiftUI: AppKit's switch turns grey while the non-activating
/// panel is not key, which hides whether it is on.
private struct PanelSwitchStyle: ToggleStyle {
    func makeBody(configuration: Configuration) -> some View {
        Button {
            configuration.isOn.toggle()
        } label: {
            HStack(alignment: .center, spacing: 10) {
                configuration.label
                    .frame(maxWidth: .infinity, alignment: .leading)
                Capsule()
                    .fill(configuration.isOn ? AnyShapeStyle(Color.accentColor) : AnyShapeStyle(.fill.secondary))
                    .frame(width: 32, height: 18)
                    .overlay(alignment: configuration.isOn ? .trailing : .leading) {
                        Circle()
                            .fill(.white)
                            .shadow(color: .black.opacity(0.2), radius: 0.5, y: 0.5)
                            .padding(2)
                    }
                    .animation(.easeOut(duration: 0.12), value: configuration.isOn)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityRepresentation {
            Toggle(isOn: configuration.$isOn) { configuration.label }
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
    let context: RequestContext
    let detail: GetDetail
    let durations: [LeaseDuration]
    let check: (String) -> Result<HostPatternCheckItem, AppError>

    @State private var hosts: [HostEntry]
    @State private var anyHost = false
    @State private var duration: UInt64
    @State private var editingHost = false
    @State private var newHost = ""
    @State private var hostError: String?
    @State private var editingReason = false
    @State private var mode: ValueMode
    /// Restarts with every mode flip, so a quick flip plus click cannot approve.
    @State private var modeArmed = false
    @FocusState private var hostFieldFocused: Bool

    init(
        context: RequestContext,
        detail: GetDetail,
        durations: [LeaseDuration],
        check: @escaping (String) -> Result<HostPatternCheckItem, AppError>
    ) {
        self.context = context
        self.detail = detail
        self.durations = durations
        self.check = check
        _hosts = State(initialValue: detail.initialHosts.map { HostEntry(pattern: $0.normalized, broad: $0.broad) })
        _duration = State(initialValue: detail.defaultDurationSecs ?? 0)
        _mode = State(initialValue: detail.rawRequested ? .realValue : .proxied)
    }

    private var raw: Bool { detail.rawRequested }
    private var durationSecs: UInt64? { duration == 0 ? nil : duration }
    private var armed: Bool { context.armed && modeArmed }
    private var canAllow: Bool {
        switch mode {
        case .proxied: armed && (anyHost || !hosts.isEmpty)
        case .realValue: armed
        }
    }
    /// Return allows only in Proxied mode, and never while typing.
    private var allowIsDefault: Bool { mode == .proxied && !hostFieldFocused && !editingReason }

    /// Requested hosts and the secret's remembered/URI hosts that are not chosen yet.
    private var suggestions: [HostEntry] {
        let present = Set(hosts.map(\.pattern))
        var seen = Set<String>()
        let broad = Dictionary(detail.suggestedHosts.map { ($0.normalized, $0.broad) }, uniquingKeysWith: { a, _ in a })
        let candidates = detail.requestedHosts + detail.suggestedHosts.map(\.normalized)
        return candidates
            .filter { $0 != "*" && !present.contains($0) && seen.insert($0).inserted }
            .map { HostEntry(pattern: $0, broad: broad[$0] ?? false) }
    }

    private var subtitle: Text {
        let name = Text(verbatim: detail.name).fontWeight(.bold)
        if raw {
            let realValue = Text("real value").foregroundStyle(.orange).fontWeight(.semibold)
            return Text("wants the \(realValue) of \(name)")
        }
        return Text("wants to use \(name)")
    }

    private var approvedHostsLine: String {
        if mode == .realValue { return String(localized: "none (real value)") }
        return anyHost ? String(localized: "any host") : hosts.map(\.pattern).joined(separator: ", ")
    }

    var body: some View {
        ApprovalScaffold(error: context.error, footnote: nil) {
            ApprovalHeader(title: context.requesterTitle, subtitle: subtitle, queue: context.queue) {
                AppIconImage()
            }
        } content: {
            ReasonBlock(reason: detail.reason)
            // Real value: the hosts do not apply, so the section leaves the layout. Its
            // state stays here, so switching back restores what the operator had.
            if mode == .proxied {
                HostsSection(
                    hosts: $hosts,
                    anyHost: $anyHost,
                    editing: $editingHost,
                    newHost: $newHost,
                    error: $hostError,
                    fieldFocused: $hostFieldFocused,
                    suggestions: suggestions,
                    add: add
                )
            }
            HStack(alignment: .center, spacing: 10) {
                SectionLabel("For")
                Picker("For", selection: $duration) {
                    ForEach(durations) { option in
                        Text(verbatim: option.title).tag(option.id)
                    }
                }
                .labelsHidden()
                .fixedSize()
                Spacer(minLength: 0)
            }
        } details: {
            InfoRow(label: "Vault", value: detail.vaultName)
            InfoRow(label: "Fields", value: detail.fields.joined(separator: ", "))
            InfoRow(label: "Requested hosts", value: detail.requestedHosts.joined(separator: ", "))
            InfoRow(label: "Approved hosts", value: approvedHostsLine)
            InfoRow(label: "Requested mode", value: raw ? String(localized: "real value") : String(localized: "proxied (sentinel)"))
            RequestMetaRows(context: context)
        } actions: {
            ApprovalActions(
                cannedReasons: ["host selection too open", "provide a better reason"],
                armed: context.armed,
                escapeDenies: !hostFieldFocused,
                editingReason: $editingReason,
                deny: context.deny
            ) {
                AllowSplitButton(mode: $mode, enabled: canAllow, isDefault: allowIsDefault, allow: allow)
            }
            ValueModeCaption(mode: mode)
        }
        .task(id: mode) {
            modeArmed = false
            try? await Task.sleep(for: .seconds(1))
            modeArmed = !Task.isCancelled
        }
        .onChange(of: mode) { _, newMode in
            if newMode == .realValue {
                editingHost = false
                newHost = ""
                hostError = nil
            }
        }
    }

    private func allow() {
        guard canAllow else { return }
        switch mode {
        case .proxied:
            context.resolve(.approveGet(raw: false, durationSecs: durationSecs, hosts: anyHost ? ["*"] : hosts.map(\.pattern)))
        case .realValue:
            context.resolve(.approveGet(raw: true, durationSecs: durationSecs, hosts: []))
        }
    }

    /// Validates with the core's rule; `*` turns on "Any host".
    private func add(_ pattern: String) -> Bool {
        switch check(pattern) {
        case let .success(result):
            hostError = nil
            if result.normalized == "*" {
                anyHost = true
                editingHost = false
            } else if !hosts.contains(where: { $0.pattern == result.normalized }) {
                hosts.append(HostEntry(pattern: result.normalized, broad: result.broad))
            }
            return true
        case let .failure(error):
            hostError = error.message
            return false
        }
    }
}

/// "Can be used with": host pills, the `+` pill that becomes an inline field with
/// suggestions and "Any host".
private struct HostsSection: View {
    @Binding var hosts: [HostEntry]
    @Binding var anyHost: Bool
    @Binding var editing: Bool
    @Binding var newHost: String
    @Binding var error: String?
    var fieldFocused: FocusState<Bool>.Binding
    let suggestions: [HostEntry]
    let add: (String) -> Bool

    private var filteredSuggestions: [HostEntry] {
        let typed = newHost.trimmingCharacters(in: .whitespaces).lowercased()
        return typed.isEmpty ? suggestions : suggestions.filter { $0.pattern.contains(typed) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            SectionLabel("Can be used with")
            VStack(alignment: .leading, spacing: 6) {
                FlowLayout(spacing: 6) {
                    if anyHost {
                        HostPill(warning: true, help: "Any host lets the agent obtain the real value.", remove: { anyHost = false }) {
                            Text("Any host")
                        }
                    } else {
                        ForEach(hosts) { entry in
                            HostPill(
                                warning: entry.broad,
                                help: entry.broad ? "Broad pattern: it matches many hosts." : nil,
                                remove: { hosts.removeAll { $0.id == entry.id } }
                            ) {
                                Text(verbatim: entry.pattern)
                            }
                        }
                        if editing {
                            HostField(text: $newHost, focused: fieldFocused, submit: submit, cancel: stopEditing)
                        } else {
                            AddPill { startEditing() }
                        }
                    }
                }
                if editing && !anyHost {
                    FlowLayout(spacing: 6) {
                        ForEach(filteredSuggestions) { suggestion in
                            Button {
                                _ = add(suggestion.pattern)
                                fieldFocused.wrappedValue = true
                            } label: {
                                Label { Text(verbatim: suggestion.pattern) } icon: { Image(systemName: "plus") }
                            }
                            .buttonStyle(SuggestionChipStyle(warning: suggestion.broad))
                            .help(suggestion.broad ? "Broad pattern: it matches many hosts." : "")
                        }
                        Button {
                            _ = add("*")
                        } label: {
                            Label("Any host", systemImage: "exclamationmark.triangle")
                        }
                        .buttonStyle(SuggestionChipStyle(warning: true))
                        .help("Any host lets the agent obtain the real value.")
                    }
                }
                if let error {
                    Text(verbatim: error).font(.caption).foregroundStyle(.red)
                }
                if anyHost {
                    Label("Any host lets the agent obtain the real value.", systemImage: "exclamationmark.triangle.fill")
                        .font(.callout)
                        .foregroundStyle(.orange)
                }
            }
        }
    }

    private func startEditing() {
        error = nil
        newHost = ""
        editing = true
    }

    private func stopEditing() {
        editing = false
        newHost = ""
        error = nil
        fieldFocused.wrappedValue = false
    }

    /// Return adds the typed host and keeps the field for another; empty Return closes it.
    private func submit() {
        let text = newHost.trimmingCharacters(in: .whitespaces)
        guard !text.isEmpty else {
            stopEditing()
            return
        }
        if add(text) {
            newHost = ""
            if !anyHost { fieldFocused.wrappedValue = true }
        }
    }
}

/// Small dashed capsule for a host that can be added.
private struct SuggestionChipStyle: ButtonStyle {
    let warning: Bool

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .labelStyle(.titleAndIcon)
            .font(.system(size: 12))
            .foregroundStyle(warning ? AnyShapeStyle(Color.orange) : AnyShapeStyle(.secondary))
            .padding(.horizontal, 9)
            .padding(.vertical, 3)
            .background(warning ? AnyShapeStyle(Color.orange.opacity(0.1)) : AnyShapeStyle(.clear), in: Capsule())
            .overlay(
                Capsule().strokeBorder(
                    warning ? AnyShapeStyle(Color.orange.opacity(0.6)) : AnyShapeStyle(.separator),
                    style: StrokeStyle(lineWidth: 1, dash: [3, 2])
                )
            )
            .contentShape(Capsule())
            .opacity(configuration.isPressed ? 0.7 : 1)
    }
}

private struct HostPill<Label: View>: View {
    let warning: Bool
    let help: LocalizedStringKey?
    let remove: () -> Void
    let label: Label
    @State private var hovering = false

    init(warning: Bool, help: LocalizedStringKey?, remove: @escaping () -> Void, @ViewBuilder label: () -> Label) {
        self.warning = warning
        self.help = help
        self.remove = remove
        self.label = label()
    }

    var body: some View {
        HStack(spacing: 4) {
            if warning {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.system(size: 10))
                    .foregroundStyle(.orange)
            }
            label
                .lineLimit(1)
                .truncationMode(.middle)
            Button(action: remove) {
                Image(systemName: "xmark.circle.fill")
                    .foregroundStyle(.secondary)
            }
            .buttonStyle(.plain)
            .opacity(hovering ? 1 : 0)
            .allowsHitTesting(hovering)
            .accessibilityHidden(true)
        }
        .font(.system(size: 13))
        .padding(.leading, 10)
        .padding(.trailing, 6)
        .padding(.vertical, 4)
        .background(
            warning ? AnyShapeStyle(Color.orange.opacity(0.14)) : AnyShapeStyle(.background.opacity(0.6)),
            in: Capsule()
        )
        .overlay(Capsule().strokeBorder(warning ? AnyShapeStyle(Color.orange.opacity(0.45)) : AnyShapeStyle(.separator), lineWidth: 0.5))
        .onHover { hovering = $0 }
        .help(help.map { Text($0) } ?? Text(verbatim: ""))
        .accessibilityElement(children: .combine)
        .accessibilityAction(named: Text("Remove"), remove)
    }
}

private struct AddPill: View {
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Image(systemName: "plus")
                .font(.system(size: 12, weight: .semibold))
                .frame(width: 30, height: 22)
                .background(.background.opacity(0.6), in: Capsule())
                .overlay(Capsule().strokeBorder(.separator, lineWidth: 0.5))
                .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .help("Add a host")
        .accessibilityLabel("Add a host")
    }
}

private struct HostField: View {
    @Binding var text: String
    var focused: FocusState<Bool>.Binding
    let submit: () -> Void
    let cancel: () -> Void

    var body: some View {
        TextField("api.example.com", text: $text)
            .textFieldStyle(.plain)
            .font(.system(size: 13))
            .focused(focused)
            .onSubmit(submit)
            .onExitCommand(perform: cancel)
            .onAppear { focused.wrappedValue = true }
            .frame(width: 170)
            .padding(.horizontal, 10)
            .padding(.vertical, 4)
            .background(.background.opacity(0.8), in: Capsule())
            .overlay(Capsule().strokeBorder(Color.accentColor.opacity(0.7), lineWidth: 1))
    }
}

// MARK: - Update

private struct UpdateApproval: View {
    let context: RequestContext
    let name: String
    let vaultID: String
    let vaultName: String
    let field: String
    let oldValue: String
    let newValue: String
    @State private var revealed = false
    @State private var editingReason = false

    var body: some View {
        ApprovalScaffold(
            error: context.error,
            footnote: Text("Approving writes the new value to \(Text(verbatim: vaultName)). Raw values of this secret handed out earlier are revoked.")
        ) {
            ApprovalHeader(
                title: context.requesterTitle,
                subtitle: Text("wants to change \(Text(verbatim: name).fontWeight(.bold))"),
                queue: context.queue
            ) {
                AppIconImage()
            }
        } content: {
            VStack(alignment: .leading, spacing: 8) {
                HStack(alignment: .firstTextBaseline) {
                    SectionLabel("Field")
                    Text(verbatim: field).font(.system(size: 13).monospaced())
                    Spacer()
                    Toggle("Reveal", isOn: $revealed)
                        .toggleStyle(.button)
                        .controlSize(.small)
                }
                Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 10, verticalSpacing: 4) {
                    GridRow {
                        Text("Old").foregroundStyle(.secondary)
                        value(oldValue, against: newValue)
                    }
                    GridRow {
                        Text("New").foregroundStyle(.secondary)
                        value(newValue, against: oldValue)
                    }
                }
                .font(.system(size: 13))
            }
            .padding(12)
            .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        } details: {
            InfoRow(label: "Vault", value: vaultName)
            InfoRow(label: "Field", value: field)
            RequestMetaRows(context: context)
        } actions: {
            ApprovalActions(
                cannedReasons: [],
                armed: context.armed,
                escapeDenies: true,
                editingReason: $editingReason,
                deny: context.deny
            ) {
                Button("Allow") {
                    guard context.armed else { return }
                    context.resolve(.approveWrite(vaultID: vaultID, collectionID: nil))
                }
                .buttonStyle(.panel)
                .keyboardShortcut(editingReason ? nil : .defaultAction)
                .disabled(!context.armed)
            }
        }
    }

    @ViewBuilder private func value(_ value: String, against other: String) -> some View {
        if revealed {
            Text(ChangedRange.highlight(value, against: other))
                .monospaced()
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        } else {
            MaskedValue(value: value)
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
    let context: RequestContext
    let name: String
    let value: String
    let targets: [AddTargetItem]

    /// Sentinel tag for "personal vault" in the collection picker.
    private static let personal = "\u{1}personal"

    @State private var revealed = false
    @State private var vaultID = ""
    @State private var collectionID = ""
    @State private var editingReason = false

    private var target: AddTargetItem? { targets.first { $0.vaultID == vaultID } }
    private var canAllow: Bool {
        context.armed && target != nil && !(target?.kind == .bitwarden && collectionID.isEmpty)
    }

    var body: some View {
        ApprovalScaffold(
            error: context.error,
            footnote: Text("The secret is saved to the chosen vault. The agent needs a separate request to use it.")
        ) {
            ApprovalHeader(
                title: context.requesterTitle,
                subtitle: Text("wants to add \(Text(verbatim: name).fontWeight(.bold))"),
                queue: context.queue
            ) {
                AppIconImage()
            }
        } content: {
            HStack(alignment: .firstTextBaseline) {
                SectionLabel("Value")
                if revealed {
                    Text(verbatim: value)
                        .font(.system(size: 13).monospaced())
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                } else {
                    MaskedValue(value: value).font(.system(size: 13))
                }
                Spacer()
                Toggle("Reveal", isOn: $revealed)
                    .toggleStyle(.button)
                    .controlSize(.small)
            }
            .padding(12)
            .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            if targets.isEmpty {
                Text("No vault can receive this secret.").foregroundStyle(.secondary)
            } else {
                Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 10, verticalSpacing: 8) {
                    GridRow {
                        SectionLabel("Save to")
                        Picker("Save to", selection: $vaultID) {
                            ForEach(targets) { target in
                                Text(verbatim: "\(target.vaultName) (\(target.kind.title))").tag(target.vaultID)
                            }
                        }
                        .labelsHidden()
                        .fixedSize()
                    }
                    if let target, target.kind == .bitwarden {
                        GridRow {
                            SectionLabel("Collection")
                            Picker("Collection", selection: $collectionID) {
                                ForEach(target.collections) { collection in
                                    Text(verbatim: collection.name).tag(collection.id)
                                }
                                if target.personalAllowed {
                                    Text("Personal vault (no organization)").tag(Self.personal)
                                }
                            }
                            .labelsHidden()
                            .fixedSize()
                        }
                    }
                }
            }
        } details: {
            RequestMetaRows(context: context)
        } actions: {
            ApprovalActions(
                cannedReasons: [],
                armed: context.armed,
                escapeDenies: true,
                editingReason: $editingReason,
                deny: context.deny
            ) {
                Button("Allow") {
                    guard canAllow else { return }
                    let collection = (target?.kind == .bitwarden && collectionID != Self.personal) ? collectionID : nil
                    context.resolve(.approveWrite(vaultID: vaultID, collectionID: collection))
                }
                .buttonStyle(.panel)
                .keyboardShortcut(editingReason ? nil : .defaultAction)
                .disabled(!canAllow)
            }
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
