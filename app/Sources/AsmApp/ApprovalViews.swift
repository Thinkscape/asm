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
    @State private var contentHeight: CGFloat = 120
    @State private var gcloudSetup = GcloudApprovalSetup()

    var body: some View {
        ScrollView {
            ApprovalContent(model: model, armed: armed, gcloudSetup: gcloudSetup)
                .padding(18)
                .onGeometryChange(for: CGFloat.self) { geometry in geometry.size.height } action: { height in
                    contentHeight = height
                }
        }
            .frame(width: 400, height: min(contentHeight, maximumPanelHeight))
            .scrollBounceBehavior(.basedOnSize)
            .modifier(PanelBackground())
            // Top-aligned, so while the panel animates a height change the content is
            // revealed or hidden at the bottom edge.
            .frame(maxHeight: .infinity, alignment: .top)
            .overlay(alignment: .topLeading) {
                CloseButton {
                    gcloudSetup.dismiss(using: model)
                    close()
                }
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
            .onChange(of: model.shownRequestID) { previous, _ in
                gcloudSetup.cancelPreparation(forRequest: previous, using: model)
            }
    }

    private var maximumPanelHeight: CGFloat {
        max(180, (NSScreen.screens.lazy.map(\.visibleFrame.height).min() ?? 800) - 40)
    }
}

private struct ApprovalContent: View {
    let model: AppModel
    let armed: Bool
    let gcloudSetup: GcloudApprovalSetup

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            if !model.brokerSessions.isEmpty {
                BrokerSessionList(model: model)
            }
            if let request = model.shownRequest {
                ApprovalBody(
                    model: model,
                    gcloudSetup: gcloudSetup,
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
            } else if model.brokerSessions.isEmpty {
                Text("No pending requests.")
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, minHeight: 120)
            }
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
    var resolutionError: String?
    var resolve: (DecisionItem) -> Void

    var error: String? { resolutionError ?? request.error }

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
    let gcloudSetup: GcloudApprovalSetup
    let request: PendingItem
    let queue: QueueInfo
    let armed: Bool

    var body: some View {
        let context = RequestContext(
            request: request,
            queue: queue,
            armed: armed,
            resolutionError: model.resolutionError(for: request.id),
            resolve: resolve
        )
        switch request.detail {
        case let .pair(info, address, code, repair):
            PairApproval(context: context, info: info, observedAddress: address, code: code, repair: repair)
        case let .get(detail):
            if detail.isGenerated || detail.requestedGeneration != nil || !detail.generatorChoices.isEmpty {
                GeneratedGetApproval(
                    context: context, detail: detail, durations: CoreBridge.leaseDurations,
                    model: model, gcloudSetup: gcloudSetup
                )
            } else {
                StaticGetApproval(context: context, detail: detail, durations: CoreBridge.leaseDurations, model: model)
            }
        case let .update(name, vaultID, vault, field, oldValue, newValue):
            UpdateApproval(
                context: context, name: name, vaultID: vaultID, vaultName: vault,
                field: field, oldValue: oldValue, newValue: newValue
            )
        case let .add(name, value, targets):
            AddApproval(context: context, name: name, value: value, targets: targets)
        case let .login(detail):
            LoginBrokerApproval(context: context, detail: detail, durations: CoreBridge.leaseDurations, model: model)
        }
    }

    private func resolve(_ decision: DecisionItem) {
        model.resolve(request.id, decision)
    }
}

// MARK: - Frame

/// Header, request-specific rows, the Request details disclosure, the core's error, the
/// action row and a footnote, in that order.
private struct ApprovalScaffold<Header: View, Content: View, Details: View, Actions: View>: View {
    let error: String?
    let footnote: Text?
    let contentHeight: CGFloat?
    let header: Header
    let content: Content
    let details: Details
    let actions: Actions

    init(
        error: String?,
        footnote: Text?,
        contentHeight: CGFloat? = nil,
        @ViewBuilder header: () -> Header,
        @ViewBuilder content: () -> Content,
        @ViewBuilder details: () -> Details,
        @ViewBuilder actions: () -> Actions
    ) {
        self.error = error
        self.footnote = footnote
        self.contentHeight = contentHeight
        self.header = header()
        self.content = content()
        self.details = details()
        self.actions = actions()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            header
            if let contentHeight {
                ScrollView {
                    VStack(alignment: .leading, spacing: 14) { content }
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(height: contentHeight)
                .scrollBounceBehavior(.basedOnSize)
            } else {
                content
            }
            ApprovalDisclosure("Request details") {
                Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 12, verticalSpacing: 4) {
                    details
                }
                .font(.system(size: 12))
            }
            if let error {
                ErrorLine(message: error)
            }
            actions
            if let footnote {
                footnote
                    .font(.caption)
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
    var plainOnly = false

    var body: some View {
        Group {
            switch mode {
            case .proxied:
                Text(plainOnly
                     ? "These fields are delivered plainly. No proxy or destination-host approval is needed."
                     : "The agent gets a sentinel that works only through the proxy, over HTTPS, for the hosts above.")
                    .foregroundStyle(.secondary)
            case .realValue:
                Label("The agent receives the real value and keeps it. It cannot be taken back.",
                      systemImage: "exclamationmark.triangle.fill")
            }
        }
        .font(.caption)
        .fixedSize(horizontal: false, vertical: true)
    }
}

struct SectionLabel: View {
    let title: LocalizedStringKey

    init(_ title: LocalizedStringKey) {
        self.title = title
    }

    var body: some View {
        Text(title)
            .font(.caption)
            .foregroundStyle(.secondary)
    }
}

/// Shared, collapsed-by-default disclosure for approval panel sections.
struct ApprovalDisclosure<Content: View>: View {
    private let title: LocalizedStringKey
    private let content: Content
    @State private var expanded = false

    init(_ title: LocalizedStringKey, @ViewBuilder content: () -> Content) {
        self.title = title
        self.content = content()
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
                        .accessibilityHidden(true)
                    Text(title)
                    Spacer()
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .foregroundStyle(.secondary)
            .accessibilityLabel(Text(title))
            .accessibilityValue(expanded ? Text("expanded") : Text("collapsed"))
            if expanded {
                content
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

/// Rows every request kind shows in Request details, after its own.
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
/// ("Approval mode") only switches the mode. Only a static proxied get is a Return action.
private struct AllowSplitButton: View {
    @Binding var mode: ValueMode
    /// The primary segment; the chevron always works.
    let enabled: Bool
    let isDefault: Bool
    var sentinelRequired = false
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
            .onKeyPress(.return) { isDefault ? .ignored : .handled }
            .disabled(!enabled)
            SegmentDivider(style: realValue ? AnyShapeStyle(.black.opacity(0.25)) : AnyShapeStyle(.white.opacity(0.45)))
            SplitChevron(label: "Approval mode") {
                var items = [
                    SplitMenuItem(title: "Allow through proxy (hidden)", checked: mode == .proxied) {
                        mode = .proxied
                    },
                ]
                if !sentinelRequired {
                    items.append(SplitMenuItem(title: "Allow real value…", checked: mode == .realValue, tint: .systemOrange) {
                        mode = .realValue
                    })
                }
                return items
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
    @Environment(\.isEnabled) private var isEnabled

    var body: some View {
        Image(systemName: "chevron.down")
            .font(.system(size: 13, weight: .semibold))
            .frame(width: 44, height: PanelButtonMetrics.height)
            .opacity(isEnabled ? 1 : 0.55)
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
        update(button, enabled: context.environment.isEnabled)
        return button
    }

    func updateNSView(_ button: SplitMenuButton, context: Context) {
        update(button, enabled: context.environment.isEnabled)
    }

    private func update(_ button: SplitMenuButton, enabled: Bool) {
        button.isEnabled = enabled
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
        guard isEnabled else { return false }
        showMenuSoon()
        return true
    }
    private func showMenuSoon() {
        DispatchQueue.main.async { [weak self] in self?.showMenu() }
    }
    override func draw(_ dirtyRect: NSRect) {}

    private func showMenu() {
        guard isEnabled else { return }
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
        guard isEnabled, actions.indices.contains(sender.tag) else { return }
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
            footnote: Text("Pairing authorizes this host to request secrets. You approve access; eligible leases may be reused within that authorization.")
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

private struct StaticGetApproval: View {
    let context: RequestContext
    let detail: GetDetail
    let durations: [LeaseDuration]
    let model: AppModel

    @State private var hosts: [HostEntry]
    @State private var anyHost = false
    @State private var duration: UInt64
    @State private var editingHost = false
    @State private var newHost = ""
    @State private var hostError: String?
    @State private var editingReason = false
    @State private var mode: ValueMode
    @State private var armedMode: ValueMode?
    @FocusState private var hostFieldFocused: Bool

    init(context: RequestContext, detail: GetDetail, durations: [LeaseDuration], model: AppModel) {
        self.context = context
        self.detail = detail
        self.durations = durations
        self.model = model
        _hosts = State(initialValue: detail.initialHosts.map { HostEntry(pattern: $0.normalized, broad: $0.broad) })
        _duration = State(initialValue: detail.defaultDurationSecs ?? 0)
        _mode = State(initialValue: detail.rawRequested && !detail.sentinelRequired && detail.login == nil ? .realValue : .proxied)
    }

    private var suggestions: [HostEntry] {
        let present = Set(hosts.map(\.pattern))
        var seen = Set<String>()
        let broad = Dictionary(detail.suggestedHosts.lazy.map { ($0.normalized, $0.broad) }, uniquingKeysWith: { a, _ in a })
        return (detail.requestedHosts + detail.suggestedHosts.map(\.normalized))
            .filter { $0 != "*" && !present.contains($0) && seen.insert($0).inserted }
            .map { HostEntry(pattern: $0, broad: broad[$0] ?? false) }
    }

    private var approvedHosts: [String] {
        guard mode == .proxied, detail.hasSubstitutableFields, detail.login == nil else { return [] }
        return anyHost ? ["*"] : hosts.map(\.pattern)
    }

    private var approvedHostsLine: String {
        if detail.login != nil {
            return detail.initialHosts.map(\.normalized).joined(separator: ", ")
        }
        if mode == .realValue { return String(localized: "none (real value)") }
        if !detail.hasSubstitutableFields { return String(localized: "not required (plain fields)") }
        return anyHost ? String(localized: "any host") : hosts.map(\.pattern).joined(separator: ", ")
    }

    private func canAllow(_ expected: ValueMode) -> Bool {
        guard context.armed, armedMode == expected, mode == expected,
              !model.isResolving(context.request.id),
              !(detail.sentinelRequired && expected == .realValue) else { return false }
        if detail.login != nil {
            return expected == .proxied && duration > 0 && duration <= Self.loginMaxSeconds
        }
        return expected == .realValue || !detail.hasSubstitutableFields || anyHost || !hosts.isEmpty
    }

    /// A login grant lasts at most an hour (the manager enforces the same limit).
    private static let loginMaxSeconds: UInt64 = 3600

    var body: some View {
        let expectedMode = mode
        let name = Text(verbatim: detail.name).fontWeight(.bold)
        let subtitle = detail.login != nil ? Text("wants to sign in with \(name)")
            : detail.rawRequested ? Text("wants the real value of \(name)") : Text("wants to use \(name)")
        ApprovalScaffold(error: context.error, footnote: nil) {
            ApprovalHeader(title: context.requesterTitle, subtitle: subtitle, queue: context.queue) { AppIconImage() }
        } content: {
            ReasonBlock(reason: detail.reason)
            VStack(alignment: .leading, spacing: 14) {
                if let url = detail.login {
                    let codes = detail.fields.contains("totp") ? String(localized: ", one-time codes") : ""
                    Text("Sign-in: \(url) · username, single-use password\(codes) · routes this site through asm until the grant expires")
                        .font(.callout)
                        .fixedSize(horizontal: false, vertical: true)
                } else if mode == .proxied {
                    if detail.hasSubstitutableFields {
                        HostsSection(
                            hosts: $hosts, anyHost: $anyHost, editing: $editingHost,
                            newHost: $newHost, error: $hostError, fieldFocused: $hostFieldFocused,
                            suggestions: suggestions, add: add
                        )
                    } else {
                        Text("Only plain fields are selected. Destination-host controls and proxy setup are not needed.")
                            .font(.callout).foregroundStyle(.secondary)
                    }
                }
                GetDurationPicker(durations: durations, duration: $duration,
                                  maxSeconds: detail.login != nil ? Self.loginMaxSeconds : nil)
                if detail.sentinelRequired && detail.login == nil {
                    Text("The requester requires sentinel delivery. Real-value disclosure is disabled.")
                        .font(.callout)
                }
            }
        } details: {
            InfoRow(label: "Vault", value: detail.vaultName)
            InfoRow(label: "Fields", value: detail.fields.joined(separator: ", "))
            InfoRow(label: "Requested hosts", value: detail.requestedHosts.joined(separator: ", "))
            InfoRow(label: "Approved hosts", value: approvedHostsLine)
            InfoRow(label: "Requested mode", value: detail.login != nil ? String(localized: "sign-in (single-use sentinel)")
                : detail.rawRequested ? String(localized: "real value") : String(localized: "proxied (sentinel)"))
            RequestMetaRows(context: context)
        } actions: {
            ApprovalActions(cannedReasons: ["host selection too open", "provide a better reason"],
                            armed: context.armed, escapeDenies: !hostFieldFocused,
                            editingReason: $editingReason, deny: context.deny) {
                AllowSplitButton(
                    mode: $mode, enabled: canAllow(expectedMode),
                    isDefault: mode == .proxied && !hostFieldFocused && !editingReason,
                    sentinelRequired: detail.sentinelRequired || detail.login != nil
                ) {
                    guard canAllow(expectedMode) else { return }
                    context.resolve(.approveGet(
                        raw: expectedMode == .realValue, durationSecs: duration == 0 ? nil : duration,
                        hosts: approvedHosts, generation: nil
                    ))
                }
            }
            if detail.login == nil {
                ValueModeCaption(mode: mode, plainOnly: !detail.hasSubstitutableFields)
            }
        }
        .task(id: expectedMode) {
            guard !Task.isCancelled else { return }
            armedMode = nil
            try? await Task.sleep(for: .seconds(1))
            if !Task.isCancelled { armedMode = expectedMode }
        }
        .onChange(of: mode) { _, newMode in
            if newMode == .realValue { editingHost = false; newHost = ""; hostError = nil }
        }
        .onChange(of: detail.sentinelRequired) { _, required in
            if required { mode = .proxied }
        }
        .onChange(of: detail.login) { _, login in
            if login != nil { mode = .proxied }
        }
    }

    private func add(_ pattern: String) -> Bool {
        switch model.checkHostPattern(pattern) {
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

// MARK: - Sign in (asm login)

private struct LoginBrokerApproval: View {
    let context: RequestContext
    let detail: LoginDetail
    let durations: [LeaseDuration]
    let model: AppModel

    /// Extra fill origins the operator removed; the URL's own origin is always filled.
    @State private var removed: Set<String> = []
    @State private var duration: UInt64 = 3600
    @State private var editingReason = false

    private var exportOrigin: String { detail.fillOrigins.first ?? "" }

    private var exportHost: String {
        URL(string: exportOrigin)?.host() ?? exportOrigin
    }

    private var canAllow: Bool {
        context.armed && duration > 0 && !model.isResolving(context.request.id)
    }

    var body: some View {
        let name = Text(verbatim: detail.name).fontWeight(.bold)
        ApprovalScaffold(error: context.error, footnote: nil) {
            ApprovalHeader(title: context.requesterTitle, subtitle: Text("wants you to sign in with \(name)"),
                           queue: context.queue) { AppIconImage() }
        } content: {
            ReasonBlock(reason: detail.reason)
            VStack(alignment: .leading, spacing: 10) {
                Text(verbatim: detail.url)
                    .font(.system(size: 13).monospaced())
                    .lineLimit(3)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                SectionLabel("Fills \(detail.name) on")
                FlowLayout {
                    ForEach(detail.fillOrigins.filter { !removed.contains($0) }, id: \.self) { origin in
                        if origin == exportOrigin {
                            Text(verbatim: origin)
                                .font(.system(size: 13))
                                .lineLimit(1)
                                .truncationMode(.middle)
                                .padding(.horizontal, 10)
                                .padding(.vertical, 4)
                                .background(.background.opacity(0.6), in: Capsule())
                                .overlay(Capsule().strokeBorder(.separator, lineWidth: 0.5))
                        } else {
                            HostPill(warning: false, help: "Remove this origin", remove: { removed.insert(origin) }) {
                                Text(verbatim: origin)
                            }
                        }
                    }
                }
                Text("Exports cookies valid for \(exportHost) and \(exportOrigin)'s localStorage")
                    .font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
                GetDurationPicker(durations: durations, duration: $duration, maxSeconds: .max)
            }
        } details: {
            InfoRow(label: "Vault", value: detail.vaultName)
            InfoRow(label: "Item", value: detail.name)
            InfoRow(label: "URL", value: detail.url)
            InfoRow(label: "Fills", value: detail.hasTotp
                    ? String(localized: "username, password, one-time codes") : String(localized: "username, password"))
            RequestMetaRows(context: context)
        } actions: {
            ApprovalActions(cannedReasons: ["provide a better reason"], armed: context.armed, escapeDenies: true,
                            editingReason: $editingReason, deny: context.deny) {
                Button("Allow") {
                    guard canAllow else { return }
                    context.resolve(.approveLogin(
                        durationSecs: duration,
                        fillOrigins: detail.fillOrigins.filter { !removed.contains($0) }
                    ))
                }
                .buttonStyle(.panel)
                .keyboardShortcut(editingReason ? nil : .defaultAction)
                .disabled(!canAllow)
            }
            Text("Opens Chrome on this Mac and fills the login; it never submits. Sign in, then choose Hand over session.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

private enum ApprovalGenerationProvider: Equatable {
    case githubApp, gcloud, gcloudAccess

    init(_ grant: GenerationGrantItem) {
        switch grant {
        case .githubApp: self = .githubApp
        case .gcloud: self = .gcloud
        case .gcloudAccess: self = .gcloudAccess
        }
    }

    init(_ request: GenerationRequestItem) {
        switch request {
        case .githubApp: self = .githubApp
        case .gcloud: self = .gcloud
        case .gcloudAccess: self = .gcloudAccess
        }
    }

    var isGoogle: Bool { self != .githubApp }

    var title: LocalizedStringKey {
        switch self {
        case .githubApp: "GitHub App"
        case .gcloud: "Google Cloud (legacy)"
        case .gcloudAccess: "Google Cloud"
        }
    }
}

private struct ApprovalGeneratorIdentity: Hashable {
    let id: GeneratorApprovalChoiceItem.ID
    let revision: UInt64

    init(_ choice: GeneratorApprovalChoiceItem) {
        id = choice.id
        revision = choice.choice.revision
    }

    func matches(_ choice: GeneratorApprovalChoiceItem) -> Bool {
        choice.id == id && choice.choice.revision == revision && choice.choice.available
    }
}

private struct GetApprovalClaims: Equatable {
    var github = GithubClaimsSelection()
    var gcloudScopes: Set<String> = []
    var gcloudPermissions: Set<GcloudPermissionItem> = []
    var gcloudProjectID: String?

    init() {}

    init(request: GenerationRequestItem?, within ceiling: GenerationGrantItem) {
        switch (request, ceiling) {
        case let (.githubApp(request)?, .githubApp(grant)):
            github = .requested(request, within: grant)
        case let (.gcloud(request)?, .gcloud(grant)):
            gcloudScopes = Set(request.scopes ?? []).intersection(grant.scopes)
        case let (.gcloudAccess(request)?, .gcloudAccess):
            gcloudProjectID = request.projectID
            gcloudPermissions = Set(request.permissions)
        default:
            break
        }
    }

    func grant(
        within ceiling: GenerationGrantItem, defaultProjectID: String?, operatorSelectedGrant: Bool
    ) -> GenerationGrantItem? {
        switch ceiling {
        case let .githubApp(grant):
            guard operatorSelectedGrant else { return .githubApp(grant) }
            let projected = github.grant(within: grant)
            guard projected.permissions.count == github.permissions.count,
                  projected.repositories.count == github.repositoryIDs.count else { return nil }
            return .githubApp(projected)
        case var .gcloud(grant):
            guard gcloudScopes.isSubset(of: Set(grant.scopes)), let defaultProjectID else { return nil }
            grant.scopes = gcloudScopes.sorted()
            grant.projectID = defaultProjectID
            return .gcloud(grant)
        case .gcloudAccess:
            return nil
        }
    }
}

private struct GetApprovalGuard: Equatable {
    var reviewRevision: UInt64
    var requestID: String
    var generator: ApprovalGeneratorIdentity?
    var claims: GetApprovalClaims
    var selection: GenerationSelectionItem?
    var request: GenerationRequestItem?
    var durationSecs: UInt64?
    var managedTarget: GcloudSetupTarget?
    var gcloudProfile: GcloudAccessGrantItem?
    var planAuthorization: GcloudPlanAuthorization?
    var resolving: Bool
    var managedPresentation: UInt64?
}

private struct GcloudPreparationKey: Equatable {
    let target: GcloudSetupTarget
    let presentation: UInt64
    let reviewRevision: UInt64
    let renewal: UInt64
}

private struct GcloudProjectLookupKey: Equatable {
    let requestID: String
    let requestExpiry: Date
    let requestedAccess: GcloudAccessRequestItem
    let generator: ApprovalGeneratorIdentity
    let presentation: UInt64
    let refresh: UInt64
}

private struct GcloudProjectLookup {
    let key: GcloudProjectLookupKey
    let list: GcloudApprovalProjectList
}

private struct GeneratedGetApproval: View {
    let context: RequestContext
    let detail: GetDetail
    let durations: [LeaseDuration]
    let model: AppModel
    let gcloudSetup: GcloudApprovalSetup

    @State private var duration: UInt64
    @State private var editingReason = false
    @State private var selectedGenerator: ApprovalGeneratorIdentity?
    @State private var claims: GetApprovalClaims
    @State private var reviewRevision: UInt64 = 0
    @State private var armedGuard: GetApprovalGuard?
    @State private var projectLookup: GcloudProjectLookup?
    @State private var projectRefresh: UInt64 = 0

    init(
        context: RequestContext,
        detail: GetDetail,
        durations: [LeaseDuration],
        model: AppModel,
        gcloudSetup: GcloudApprovalSetup
    ) {
        self.context = context
        self.detail = detail
        self.durations = durations
        self.model = model
        self.gcloudSetup = gcloudSetup
        _duration = State(initialValue: detail.defaultDurationSecs ?? 0)
        let initial = Self.soleAvailableGenerator(in: detail)
        _selectedGenerator = State(initialValue: initial.map(ApprovalGeneratorIdentity.init))
        _claims = State(initialValue: initial.map {
            GetApprovalClaims(request: detail.requestedGeneration, within: $0.choice.ceiling)
        } ?? GetApprovalClaims())
    }

    private static func soleAvailableGenerator(in detail: GetDetail) -> GeneratorApprovalChoiceItem? {
        // One ready generator among several choices is not a default identity.
        guard detail.generatorChoices.count == 1, let option = detail.generatorChoices.first,
              canSelect(option, in: detail) else { return nil }
        return option
    }

    private static func canSelect(_ option: GeneratorApprovalChoiceItem, in detail: GetDetail) -> Bool {
        guard option.choice.available, detail.vaultID == nil || detail.vaultID == option.choice.id else { return false }
        let provider = ApprovalGenerationProvider(option.choice.ceiling)
        if let request = detail.requestedGeneration, ApprovalGenerationProvider(request) != provider { return false }
        return true
    }

    private var durationSecs: UInt64? { duration == 0 ? nil : duration }
    private var selected: GeneratorApprovalChoiceItem? {
        guard let selectedGenerator else { return nil }
        return detail.generatorChoices.first(where: selectedGenerator.matches)
    }
    private var provider: ApprovalGenerationProvider? {
        if let request = detail.requestedGeneration { return ApprovalGenerationProvider(request) }
        return (selected ?? detail.generatorChoices.first).map { ApprovalGenerationProvider($0.choice.ceiling) }
    }
    private var managedAccess: GcloudAccessRequestItem? {
        if case let .gcloudAccess(access)? = detail.requestedGeneration { return access }
        return nil
    }
    private var projectLookupKey: GcloudProjectLookupKey? {
        let presentation = model.approvalPresentation
        guard !detail.sentinelRequired, detail.operatorSelectedGcloudProject, let original = managedAccess,
              let selected, selected.choice.ceiling == .gcloudAccess(.requested(access: original)),
              gcloudSetup.isPresented(presentation) else { return nil }
        return GcloudProjectLookupKey(
            requestID: context.request.id, requestExpiry: context.request.expiresAt,
            requestedAccess: original, generator: ApprovalGeneratorIdentity(selected),
            presentation: presentation, refresh: projectRefresh
        )
    }

    private var projectList: GcloudApprovalProjectList? {
        guard let key = projectLookupKey else { return nil }
        guard let projectLookup, projectLookup.key == key else { return .loading }
        if case let .loaded(_, expiresAt) = projectLookup.list, expiresAt <= .now { return .expired }
        return projectLookup.list
    }

    private var reviewedProjectID: String? {
        guard let project = claims.gcloudProjectID else { return nil }
        if project == managedAccess?.projectID { return project }
        guard case let .loaded(alternatives, _)? = projectList, alternatives.contains(project) else { return nil }
        return project
    }

    private func managedTarget(for selected: GeneratorApprovalChoiceItem, projectID: String?) -> GcloudSetupTarget? {
        guard !detail.sentinelRequired, let original = managedAccess, let projectID,
              selected.choice.ceiling == .gcloudAccess(.requested(access: original)) else { return nil }
        let access = detail.operatorSelectedGrant
            ? original.selecting(projectID: projectID, permissions: claims.gcloudPermissions)
            : GcloudAccessRequestItem(projectID: projectID, permissions: original.permissions)
        guard !access.permissions.isEmpty else { return nil }
        return GcloudSetupTarget(
            requestID: context.request.id, requestExpiry: context.request.expiresAt,
            requestedAccess: original, access: access,
            selection: GenerationSelectionItem(
                generatorID: selected.choice.id, generatorRevision: selected.choice.revision,
                grant: .gcloudAccess(.requested(access: access))
            ),
            durationSecs: durationSecs
        )
    }
    private var guardValue: GetApprovalGuard {
        let request = detail.requestedGeneration
        let selected = self.selected
        let projectID = reviewedProjectID
        let managedTarget = selected.flatMap { self.managedTarget(for: $0, projectID: projectID) }
        let ready = selected.flatMap { managedTarget?.readyGrant(in: $0) }
        let selection = selected.flatMap { generator -> GenerationSelectionItem? in
            guard !detail.sentinelRequired else { return nil }
            if case .gcloudAccess = generator.choice.ceiling { return managedTarget?.selection }
            guard let grant = claims.grant(
                within: generator.choice.ceiling, defaultProjectID: generator.defaultProjectID,
                operatorSelectedGrant: detail.operatorSelectedGrant
            ) else { return nil }
            if let request, ApprovalGenerationProvider(request) != ApprovalGenerationProvider(grant) { return nil }
            if !detail.operatorSelectedGrant, case let .githubApp(grant) = grant {
                guard case let .githubApp(scope)? = request, generator.scopeIssues.isEmpty,
                      grant.exactlyMatches(scope) else { return nil }
            }
            return GenerationSelectionItem(generatorID: generator.choice.id, generatorRevision: generator.choice.revision, grant: grant)
        }
        return GetApprovalGuard(
            reviewRevision: reviewRevision,
            requestID: context.request.id,
            generator: selectedGenerator, claims: claims, selection: selection, request: request,
            durationSecs: durationSecs,
            managedTarget: managedTarget, gcloudProfile: ready,
            planAuthorization: ready == nil ? managedTarget.flatMap { gcloudSetup.status(for: $0).authorization } : nil,
            resolving: model.isResolving(context.request.id),
            managedPresentation: provider == .gcloudAccess ? model.approvalPresentation : nil
        )
    }

    private func canGenerate(_ approval: GetApprovalGuard) -> Bool {
        guard context.armed, armedGuard == approval, !approval.resolving,
              context.request.expiresAt > .now, let grant = approval.selection?.grant else { return false }
        switch grant {
        case let .githubApp(grant):
            return !grant.repositories.isEmpty && grant.repositories.count <= 500
                && grant.permissions.contains { $0.name == "metadata" && $0.level == .read }
        case let .gcloud(grant):
            return !grant.scopes.isEmpty
        case .gcloudAccess(.requested):
            guard approval.managedTarget != nil,
                  let presentation = approval.managedPresentation, gcloudSetup.isPresented(presentation) else { return false }
            if approval.gcloudProfile != nil { return true }
            guard let authorization = approval.planAuthorization else { return false }
            return authorization.expiresAt > .now
        case .gcloudAccess:
            return false
        }
    }

    private var subtitle: Text {
        let name = Text(verbatim: detail.name).fontWeight(.bold)
        if provider?.isGoogle == true { return Text("is requesting a Google Cloud token") }
        return Text("requested a new \(name)")
    }

    var body: some View {
        let expectedGuard = guardValue
        let setupTarget = expectedGuard.gcloudProfile == nil ? expectedGuard.managedTarget : nil
        let setupStatus = setupTarget.map { gcloudSetup.status(for: $0) }
        let preparationKey = setupTarget.flatMap { target -> GcloudPreparationKey? in
            guard !expectedGuard.resolving, let presentation = expectedGuard.managedPresentation,
                  gcloudSetup.isPresented(presentation) else { return nil }
            return GcloudPreparationKey(
                target: target, presentation: presentation, reviewRevision: expectedGuard.reviewRevision,
                renewal: gcloudSetup.renewal
            )
        }
        let provider = self.provider
        let projectLookupKey = self.projectLookupKey
        ApprovalScaffold(
            error: context.resolutionError ?? setupStatus?.error ?? context.request.error,
            footnote: detail.sentinelRequired ? nil : Text("The paired host receives the raw token. Agent labels identify the requester but are not a security boundary."),
            contentHeight: max(160, min(340, (NSScreen.main?.visibleFrame.height ?? 800) - 460))
        ) {
            ApprovalHeader(title: context.requesterTitle, subtitle: subtitle, queue: context.queue) { AppIconImage() }
        } content: {
            ReasonBlock(reason: detail.reason)
            VStack(alignment: .leading, spacing: 14) {
                if detail.sentinelRequired {
                    Text("This request cannot accept a raw token. Deny it and ask the requester to retry with raw delivery.")
                        .font(.callout)
                } else {
                    GeneratorApprovalSection(
                        provider: provider, choices: detail.generatorChoices, pinnedID: detail.vaultID,
                        selected: selected, claims: reviewBinding($claims),
                        request: detail.requestedGeneration, operatorSelectedGrant: detail.operatorSelectedGrant,
                        approvedGrant: expectedGuard.selection?.grant,
                        projects: projectList, selectedProjectID: reviewedProjectID,
                        selectProject: { selectProject($0, from: projectLookupKey) },
                        reloadProjects: { reloadProjects(from: projectLookupKey) },
                        select: { id in selectGenerator(id) }
                    )
                    GetDurationPicker(durations: durations, duration: reviewBinding($duration))
                }
                if provider == .gcloudAccess, !expectedGuard.resolving {
                    if case let .issued(_, uniqueID, email)? = expectedGuard.gcloudProfile {
                        GcloudManagedServiceAccount(email: email, uniqueID: uniqueID)
                        Text("This profile already exists. Approval makes no IAM changes.")
                            .font(.caption).foregroundStyle(.secondary)
                    } else if case .preparing? = setupStatus {
                        Text("Checking IAM for these permissions…").font(.caption).foregroundStyle(.secondary)
                    } else if case .failed? = setupStatus, let setupTarget {
                        Button("Retry IAM check") { gcloudSetup.retry(for: setupTarget, using: model) }
                    }
                }
            }
            .disabled(expectedGuard.resolving)
        } details: {
            InfoRow(label: "Generator", value: selected?.choice.name ?? detail.vaultName)
            InfoRow(label: "Output", value: detail.name)
            if case let .gcloud(grant)? = expectedGuard.selection?.grant, let projectID = grant.projectID {
                InfoRow(label: "Issuance quota project", value: projectID)
            }
            InfoRow(label: "Fields", value: detail.fields.joined(separator: ", "))
            RequestMetaRows(context: context)
            GeneratedCredentialNotes(provider: provider)
        } actions: {
            // Keep durable changes next to the decision, outside the scrollable claim editor.
            if case let .prepared(authorization, plan)? = setupStatus {
                GcloudInlineIAMPlan(plan: plan)
                    .id(authorization.id)
            }
            ApprovalActions(cannedReasons: ["provide a better reason"], armed: context.armed,
                            escapeDenies: true, editingReason: $editingReason, deny: deny) {
                GenerateTokenButton(
                    generating: model.isGenerating(context.request.id), enabled: canGenerate(expectedGuard)
                ) {
                    generate(expectedGuard)
                }
            }
            .disabled(expectedGuard.resolving)
        }
        .task(id: projectLookupKey) {
            if let projectLookupKey { await lookupProjects(for: projectLookupKey) }
        }
        .task(id: preparationKey) {
            guard !Task.isCancelled, let preparationKey, preparationKey.reviewRevision == reviewRevision,
                  gcloudSetup.isPresented(preparationKey.presentation) else { return }
            await gcloudSetup.prepare(for: preparationKey.target, using: model)
        }
        .task(id: expectedGuard) {
            guard !Task.isCancelled else { return }
            armedGuard = nil
            try? await Task.sleep(for: .seconds(1))
            if !Task.isCancelled { armedGuard = expectedGuard }
        }
        .onChange(of: detail.generatorChoices) { _, updated in
            if let selectedGenerator, updated.contains(where: selectedGenerator.matches) { return }
            setGenerator(Self.soleAvailableGenerator(in: detail))
        }
        .onChange(of: detail.requestedGeneration) { _, _ in resetClaims() }
        .onChange(of: detail.operatorSelectedGrant) { _, _ in resetClaims() }
        .onChange(of: detail.operatorSelectedGcloudProject) { _, _ in
            resetClaims()
            projectLookup = nil
        }
        .onChange(of: detail.sentinelRequired) { _, _ in invalidateReview() }
    }

    private func lookupProjects(for key: GcloudProjectLookupKey) async {
        guard key.requestExpiry > .now, isCurrentProjectLookup(key) else { return }
        clearAlternateProject()
        projectLookup = GcloudProjectLookup(key: key, list: .loading)
        // Core starts its two-minute evidence lifetime when discovery completes.
        // Start the UI deadline at dispatch (whole seconds like core) to expire no later.
        let lookupStart = Date.now.timeIntervalSince1970.rounded(.down)
        let expiresAt = min(key.requestExpiry, Date(timeIntervalSince1970: lookupStart + 120))
        do {
            let projects = try await model.gcloudApprovalProjects(
                requestID: key.requestID, generatorID: key.generator.id.generatorID,
                generatorRevision: key.generator.revision
            )
            guard isCurrentProjectLookup(key) else { return }
            guard expiresAt > .now else {
                projectLookup = GcloudProjectLookup(key: key, list: .expired)
                return
            }
            let alternatives = projects.filter { $0 != key.requestedAccess.projectID }
            projectLookup = GcloudProjectLookup(key: key, list: .loaded(alternatives: alternatives, expiresAt: expiresAt))
        } catch {
            guard isCurrentProjectLookup(key) else { return }
            projectLookup = GcloudProjectLookup(key: key, list: .failed(error.localizedDescription))
            return
        }
        try? await Task.sleep(for: .seconds(max(0, expiresAt.timeIntervalSinceNow)))
        guard isCurrentProjectLookup(key) else { return }
        clearAlternateProject()
        projectLookup = GcloudProjectLookup(key: key, list: .expired)
    }

    private func isCurrentProjectLookup(_ key: GcloudProjectLookupKey) -> Bool {
        guard !Task.isCancelled, key == projectLookupKey, let pending = model.shownRequest,
              pending.id == key.requestID, pending.expiresAt == key.requestExpiry,
              case let .get(live) = pending.detail, !live.sentinelRequired, live.operatorSelectedGcloudProject,
              case let .gcloudAccess(original)? = live.requestedGeneration,
              original == key.requestedAccess else { return false }
        return live.generatorChoices.contains {
            key.generator.matches($0) && $0.choice.ceiling == .gcloudAccess(.requested(access: original))
        }
    }

    private func selectProject(_ projectID: String?, from key: GcloudProjectLookupKey?) {
        guard let key, key.requestExpiry > .now, !model.isResolving(key.requestID),
              isCurrentProjectLookup(key) else { return }
        guard claims.gcloudProjectID != projectID else { return }
        if let projectID, projectID != key.requestedAccess.projectID {
            guard case let .loaded(alternatives, _)? = projectList, alternatives.contains(projectID) else { return }
        }
        invalidateReview()
        claims.gcloudProjectID = projectID
    }

    private func reloadProjects(from key: GcloudProjectLookupKey?) {
        guard let key, key.requestExpiry > .now, !model.isResolving(key.requestID),
              isCurrentProjectLookup(key) else { return }
        invalidateReview()
        if claims.gcloudProjectID != key.requestedAccess.projectID { claims.gcloudProjectID = nil }
        projectLookup = nil
        projectRefresh &+= 1
    }

    private func clearAlternateProject() {
        guard let project = claims.gcloudProjectID, project != managedAccess?.projectID else { return }
        invalidateReview()
        claims.gcloudProjectID = nil
    }

    private func selectGenerator(_ id: GeneratorApprovalChoiceItem.ID?) {
        let candidate = id.flatMap { id in
            detail.generatorChoices.first {
                $0.id == id && Self.canSelect($0, in: detail)
            }
        }
        guard id == nil || candidate != nil else { return }
        setGenerator(candidate)
    }

    private func setGenerator(_ candidate: GeneratorApprovalChoiceItem?) {
        let identity = candidate.map(ApprovalGeneratorIdentity.init)
        guard identity != selectedGenerator else { return }
        invalidateReview()
        selectedGenerator = identity
        projectLookup = nil
        claims = candidate.map { GetApprovalClaims(request: detail.requestedGeneration, within: $0.choice.ceiling) }
            ?? GetApprovalClaims()
    }

    private func resetClaims() {
        invalidateReview()
        claims = selected.map { GetApprovalClaims(request: detail.requestedGeneration, within: $0.choice.ceiling) }
            ?? GetApprovalClaims()
    }

    private func invalidateReview() {
        // A->B->A must not resurrect an armed button or an already prepared IAM plan.
        reviewRevision &+= 1
        armedGuard = nil
        if provider == .gcloudAccess {
            gcloudSetup.cancelPreparation(forRequest: context.request.id, using: model)
        }
    }

    private func reviewBinding<Value: Equatable>(_ value: Binding<Value>) -> Binding<Value> {
        Binding(get: { value.wrappedValue }, set: { updated in
            guard updated != value.wrappedValue else { return }
            invalidateReview()
            value.wrappedValue = updated
        })
    }

    private func generate(_ expected: GetApprovalGuard) {
        let approval = guardValue
        guard approval == expected, canGenerate(approval), let selection = approval.selection,
              let current = model.shownRequest, current.id == approval.requestID,
              case let .get(liveDetail) = current.detail, liveDetail == detail else { return }
        if let target = approval.managedTarget {
            gcloudSetup.approve(target, authorization: approval.planAuthorization, ready: approval.gcloudProfile, using: model)
        } else {
            context.resolve(.approveGet(raw: true, durationSecs: approval.durationSecs, hosts: [], generation: selection))
        }
    }

    private func deny(_ reason: String) {
        guard !model.isResolving(context.request.id) else { return }
        if provider == .gcloudAccess {
            gcloudSetup.deny(context.request.id, reason: reason, using: model)
        } else {
            context.deny(reason)
        }
    }
}

private struct GenerateTokenButton: View {
    let generating: Bool
    let enabled: Bool
    let generate: () -> Void

    var body: some View {
        Button(action: generate) {
            if generating {
                HStack(spacing: 6) {
                    ProgressView()
                        .progressViewStyle(.circular)
                        .controlSize(.small)
                        .tint(.white)
                        .accessibilityHidden(true)
                    Text("Generating…")
                }
            } else {
                Text("Generate token")
            }
        }
        .buttonStyle(.panel)
        .onKeyPress(.return) { .handled }
        .disabled(!enabled)
    }
}

private struct GetDurationPicker: View {
    let durations: [LeaseDuration]
    @Binding var duration: UInt64
    /// Offer only limited durations up to this many seconds.
    var maxSeconds: UInt64? = nil

    private var offered: [LeaseDuration] {
        guard let maxSeconds else { return durations }
        return durations.filter { $0.seconds.map { $0 <= maxSeconds } ?? false }
    }

    var body: some View {
        HStack(alignment: .center, spacing: 10) {
            SectionLabel("For")
            Picker("For", selection: $duration) {
                ForEach(offered) { option in Text(verbatim: option.title).tag(option.id) }
            }
            .labelsHidden()
            Spacer(minLength: 0)
        }
    }
}

private struct GeneratorApprovalSection: View {
    let provider: ApprovalGenerationProvider?
    let choices: [GeneratorApprovalChoiceItem]
    let pinnedID: String?
    let selected: GeneratorApprovalChoiceItem?
    @Binding var claims: GetApprovalClaims
    let request: GenerationRequestItem?
    let operatorSelectedGrant: Bool
    let approvedGrant: GenerationGrantItem?
    let projects: GcloudApprovalProjectList?
    let selectedProjectID: String?
    let selectProject: (String?) -> Void
    let reloadProjects: () -> Void
    let select: @MainActor @Sendable (GeneratorApprovalChoiceItem.ID?) -> Void

    private var githubRequest: GithubScopeRequestItem? {
        if case let .githubApp(scope)? = request { return scope }
        return nil
    }

    private var githubCeiling: GithubGrantItem? {
        if case let .githubApp(grant)? = selected?.choice.ceiling { return grant }
        return nil
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            GeneratorChoicePicker(provider: provider, choices: choices, pinnedID: pinnedID,
                                  selectedID: selected?.id, select: select)
            if selected == nil && choices.count > 1 {
                Text("Choose one identity before editing access. Grants are never combined across identities.")
                    .font(.callout).foregroundStyle(.secondary)
            }
            switch provider {
            case .githubApp:
                if operatorSelectedGrant {
                    GithubClaimsEditor(ceiling: githubCeiling, selection: $claims.github, request: githubRequest)
                    if githubCeiling != nil && claims.github.repositoryIDs.isEmpty {
                        Text("Select at least one repository.").font(.callout).foregroundStyle(.secondary)
                    }
                } else if case let .githubApp(grant)? = approvedGrant {
                    ReadOnlyApprovalScope(grant: grant)
                } else {
                    if let selected {
                        if selected.scopeIssues.isEmpty {
                            Text("This installation cannot be approved for the exact requested scope.").font(.callout)
                        } else {
                            ForEach(selected.scopeIssues, id: \.self) { issue in Text(issue).font(.callout) }
                        }
                    }
                    if let githubRequest {
                        GithubClaimsEditor(ceiling: nil, selection: $claims.github, request: githubRequest)
                    }
                }
            case .gcloud:
                if let selected, case let .gcloud(ceiling) = selected.choice.ceiling {
                    ForEach(selected.scopeIssues, id: \.self) { issue in Text(issue).font(.caption) }
                    GcloudApprovalClaims(
                        email: ceiling.serviceAccountEmail, uniqueID: ceiling.serviceAccountUniqueID,
                        defaultProjectID: selected.defaultProjectID, options: selected.scopeCatalog,
                        scopes: $claims.gcloudScopes
                    )
                    .id(ApprovalGeneratorIdentity(selected))
                }
                if case let .gcloud(scope)? = request, let scopes = scope.scopes {
                    SectionLabel("Requested OAuth scopes").accessibilityAddTraits(.isHeader)
                    GcloudScopeURIList(scopes: scopes)
                }
            case .gcloudAccess:
                if case let .gcloudAccess(scope)? = request {
                    let editable = operatorSelectedGrant && selected != nil
                    GcloudAccessClaimsEditor(
                        request: scope, allowed: editable ? GcloudPermissionItem.allCases : [],
                        selection: editable ? $claims.gcloudPermissions : .constant(Set(scope.permissions)),
                        projects: projects, selectedProjectID: selectedProjectID,
                        selectProject: selectProject, reloadProjects: reloadProjects
                    )
                    if editable && claims.gcloudPermissions.isEmpty {
                        Text("Select at least one permission.").font(.callout).foregroundStyle(.secondary)
                    }
                }
            case nil:
                EmptyView()
            }
        }
    }
}

private struct ReadOnlyApprovalScope: View {
    let grant: GithubGrantItem

    var body: some View {
        Group {
            if let owner = grant.repositoryOwner {
                LabeledContent("Repository owner", value: owner)
            }
            LabeledContent("Selected installation ID", value: String(grant.installationID))
            ScopeSummaryHeading("Scope to approve")
            GrantScopeSummary(grant: grant)
            Text("A GitHub token is issued for exactly the requested scope, from one installation.")
                .font(.callout).foregroundStyle(.secondary)
        }
    }
}

private struct GeneratorChoicePicker: View {
    let provider: ApprovalGenerationProvider?
    let choices: [GeneratorApprovalChoiceItem]
    let pinnedID: String?
    let selectedID: GeneratorApprovalChoiceItem.ID?
    let select: @MainActor @Sendable (GeneratorApprovalChoiceItem.ID?) -> Void

    private var labels: (
        title: LocalizedStringKey, prompt: LocalizedStringKey,
        selectSingle: LocalizedStringKey, empty: LocalizedStringKey
    ) {
        switch provider {
        case .githubApp:
            ("GitHub App installation", "Choose an installation…", "Select this installation",
             "No GitHub App installations match this request.")
        case .gcloudAccess:
            ("Google Cloud connection", "Choose a connection…", "Select this connection",
             "No Google Cloud connections match this request.")
        default:
            (provider?.title ?? "Generator", "Choose a generator…", "Select this generator",
             "No generators are currently available.")
        }
    }

    var body: some View {
        let choices = pinnedID.map { id in self.choices.filter { $0.choice.id == id } } ?? self.choices
        let commonApp = choices.first.flatMap { first -> String? in
            guard provider == .githubApp, choices.dropFirst().allSatisfy({ $0.choice.id == first.choice.id }) else { return nil }
            return first.choice.name
        }
        VStack(alignment: .leading, spacing: 6) {
            SectionLabel(commonApp == nil ? labels.title : "GitHub App").accessibilityAddTraits(.isHeader)
            if let commonApp { Text(verbatim: commonApp).font(.body) }
            if choices.count == 1, let sole = choices.first {
                label(sole, showAppName: commonApp == nil)
                    .font(commonApp == nil ? .body : .caption)
                    .foregroundStyle(commonApp == nil ? .primary : .secondary)
                if selectedID == nil && sole.choice.available {
                    Button(labels.selectSingle) { select(sole.id) }
                }
            } else if !choices.isEmpty {
                connectionPicker(choices, showAppName: commonApp == nil).labelsHidden()
            } else {
                Text(labels.empty).font(.callout)
            }
            ForEach(choices) { option in
                if !option.choice.available {
                    let reason = option.choice.unavailableReason ?? String(localized: "Unavailable")
                    Text("\(identityLabel(option)): \(reason)").font(.callout)
                }
            }
        }
    }

    private func connectionPicker(_ choices: [GeneratorApprovalChoiceItem], showAppName: Bool) -> some View {
        Picker(labels.title, selection: Binding(get: { selectedID }, set: { value in select(value) })) {
            Text(labels.prompt).tag(Optional<GeneratorApprovalChoiceItem.ID>.none)
            ForEach(choices) { option in
                label(option, showAppName: showAppName)
                    .tag(Optional(option.id)).disabled(!option.choice.available)
            }
        }
    }

    private func label(_ option: GeneratorApprovalChoiceItem, showAppName: Bool) -> Text {
        let title = identityLabel(option, showAppName: showAppName)
        return option.choice.available ? title : Text("\(title) (unavailable)")
    }

    private func identityLabel(_ option: GeneratorApprovalChoiceItem, showAppName: Bool = true) -> Text {
        let name = option.choice.name
        switch option.choice.ceiling {
        case let .githubApp(grant):
            let id = String(grant.installationID)
            if !showAppName {
                if let owner = grant.repositoryOwner { return Text("\(owner) · installation \(id)") }
                return Text("Installation \(id)")
            }
            if let owner = grant.repositoryOwner {
                return Text("\(name) · \(owner) · installation \(id)")
            }
            return Text("\(name) · installation \(id)")
        case let .gcloud(grant):
            return Text("\(name) · \(grant.serviceAccountEmail)")
        case .gcloudAccess:
            return Text(verbatim: name)
        }
    }
}

private struct GcloudApprovalClaims: View {
    let email: String
    let uniqueID: String
    let defaultProjectID: String?
    let options: [GcloudScopeOptionItem]
    @Binding var scopes: Set<String>

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            GcloudServiceAccountSummary(email: email, uniqueID: uniqueID)
            if let defaultProjectID {
                LabeledContent("Saved issuance quota project") {
                    Text(verbatim: defaultProjectID).monospaced().textSelection(.enabled)
                }
                Text(GcloudIAMWarning.issuanceProjectText).font(.caption).foregroundStyle(.secondary)
            } else {
                Text("The saved default project is unavailable for this generator revision.").font(.callout)
            }
            Text(GcloudIAMWarning.text).font(.callout).fixedSize(horizontal: false, vertical: true)
            Text("OAuth scopes to approve").font(.subheadline.weight(.semibold)).accessibilityAddTraits(.isHeader)
            if scopes.isEmpty {
                Text("Select at least one scope.").font(.callout).foregroundStyle(.secondary)
            } else {
                GcloudScopeURIList(scopes: scopes.sorted())
                if scopes.contains(where: GcloudIAMWarning.isCrossService) {
                    Label(GcloudIAMWarning.crossServiceText, systemImage: "exclamationmark.triangle")
                        .font(.callout).fixedSize(horizontal: false, vertical: true)
                }
            }
            ForEach(options) { option in
                Toggle(isOn: $scopes[containsScope: option.uri]) {
                    VStack(alignment: .leading, spacing: 3) {
                        Text(verbatim: option.uri).font(.caption.monospaced())
                        Text(verbatim: option.description).font(.caption).foregroundStyle(.secondary)
                    }
                    .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }
}

private extension Set where Element == String {
    subscript(containsScope scope: String) -> Bool {
        get { contains(scope) }
        set {
            if newValue { insert(scope) } else { remove(scope) }
        }
    }
}

private struct GeneratedCredentialNotes: View {
    let provider: ApprovalGenerationProvider?

    var body: some View {
        Group {
            switch provider {
            case .githubApp:
                Text("GitHub tokens expire after one hour. Run asm get again to refresh within this lease. Renewal does not extend the authorization deadline.")
            case .gcloud:
                Text("Run asm get again to refresh within this lease.")
                Text(GcloudTokenWarning.text)
            case .gcloudAccess:
                Text(GcloudTokenWarning.text)
            case nil:
                EmptyView()
            }
        }
        .font(.callout)
        .fixedSize(horizontal: false, vertical: true)
    }
}

struct GcloudManagedServiceAccount: View {
    let email: String
    let uniqueID: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            SectionLabel("Service account")
                .accessibilityAddTraits(.isHeader)
            identifier(email)
            if let uniqueID {
                LabeledContent {
                    identifier(uniqueID)
                } label: {
                    SectionLabel("Unique ID")
                }
            }
        }
    }

    private func identifier(_ value: String) -> some View {
        Text(verbatim: value)
            .font(.callout.weight(.regular))
            .foregroundStyle(.primary)
            .textSelection(.enabled)
            .fixedSize(horizontal: false, vertical: true)
    }
}

struct GcloudServiceAccountSummary: View {
    let email: String
    let uniqueID: String

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Service account").font(.subheadline.weight(.semibold)).accessibilityAddTraits(.isHeader)
            Text(verbatim: email).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
            LabeledContent("Unique ID") { Text(verbatim: uniqueID).monospaced().textSelection(.enabled) }
        }
    }
}

struct GcloudScopeURIList: View {
    let scopes: [String]

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            ForEach(scopes, id: \.self) { uri in
                Text(verbatim: uri)
                    .font(.callout.monospaced())
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

enum GcloudTokenWarning {
    static var text: LocalizedStringKey {
        "Google access tokens cannot be individually revoked. Ending this lease stops ASM delivery; copies remain usable until credential expiry."
    }

    static var clientUsage: LocalizedStringKey {
        "gcloud reads CLOUDSDK_AUTH_ACCESS_TOKEN. Other clients may need explicit bearer-token support."
    }
}

enum GcloudIAMWarning {
    static var text: LocalizedStringKey {
        "OAuth scopes can restrict API calls but do not create an exclusive service or resource allowlist. IAM grants can broaden or narrow access outside ASM without changing the saved scope ceiling."
    }

    static var issuanceProjectText: LocalizedStringKey {
        "ASM uses this project for token issuance quota. It does not change the service account or scopes, restrict resource access, or set the project for gcloud commands that use the token."
    }

    static var crossServiceText: LocalizedStringKey {
        "Cross-service scope; IAM determines accessible services and resources."
    }

    static func isCrossService(_ uri: String) -> Bool {
        uri == "https://www.googleapis.com/auth/cloud-platform" ||
            uri == "https://www.googleapis.com/auth/cloud-platform.read-only"
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
        guard context.armed, let target else { return false }
        return target.kind != .bitwarden || hasSelectedCollection(in: target)
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
                            if target == nil { Text("Choose a vault…").tag("") }
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
                                if !hasSelectedCollection(in: target) {
                                    Text("Choose a collection…").tag("")
                                }
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
        .onChange(of: targets) { _, _ in
            guard let target else {
                vaultID = ""
                collectionID = ""
                return
            }
            if !hasSelectedCollection(in: target) { collectionID = "" }
        }
    }

    private func hasSelectedCollection(in target: AddTargetItem) -> Bool {
        (collectionID == Self.personal && target.personalAllowed)
            || target.collections.contains(where: { $0.id == collectionID })
    }

    private func select(_ id: String) {
        vaultID = id
        guard let target = targets.first(where: { $0.vaultID == id }) else { return }
        if hasSelectedCollection(in: target) { return }
        collectionID = target.collections.first?.id ?? (target.personalAllowed ? Self.personal : "")
    }
}
