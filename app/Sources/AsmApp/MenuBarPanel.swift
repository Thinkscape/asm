import AppKit
import SwiftUI

struct MenuBarLabel: View {
    let model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        let alert = model.proxyStatus.needsAttention
        let glyph = alert ? MenuBarGlyph.alertImage : MenuBarGlyph.image
        let pendingCount = model.pending.count
        Group {
            if pendingCount > 0 {
                Text("\(Image(nsImage: glyph)) \(pendingCount)")
            } else {
                Image(nsImage: glyph)
            }
        }
        .accessibilityLabel(alert ? Text("Proxy not running") : Text("Agents Secrets Manager"))
        // The label lives as long as the app: lend its `openWindow` to the model (used by
        // notification clicks, which have no view).
        .onAppear { model.openWindow = { openWindow(id: $0) } }
    }
}

/// The app icon's padlock robot as a vector image for the menu bar: rounded shackle,
/// rounded body with a pill-shaped visor cut out, two oval eyes in the visor.
enum MenuBarGlyph {
    /// Template image (macOS tints it for the menu bar).
    @MainActor static let image: NSImage = {
        let image = NSImage(size: NSSize(width: 18, height: 18), flipped: true) { _ in
            guard let ctx = NSGraphicsContext.current?.cgContext else { return false }
            drawRobot(ctx, color: .black)
            return true
        }
        image.isTemplate = true
        image.accessibilityDescription = "Agents Secrets Manager"
        return image
    }()

    /// The glyph with a red dot badge (top right) while the proxy is down. A template
    /// image cannot carry colour, so this one draws the robot itself in the menu bar's
    /// text colour for the appearance it is drawn in.
    @MainActor static let alertImage: NSImage = {
        let image = NSImage(size: NSSize(width: 18, height: 18), flipped: true) { _ in
            guard let ctx = NSGraphicsContext.current?.cgContext else { return false }
            let dark = NSAppearance.currentDrawing().bestMatch(from: [.aqua, .darkAqua]) == .darkAqua
            drawRobot(ctx, color: dark ? CGColor(gray: 1, alpha: 1) : CGColor(gray: 0, alpha: 0.85))
            let badge = CGRect(x: 11.5, y: 0, width: 6.5, height: 6.5)
            // Clear a ring around the dot so it reads against the shackle.
            ctx.setBlendMode(.clear)
            ctx.fillEllipse(in: badge.insetBy(dx: -1.2, dy: -1.2))
            ctx.setBlendMode(.normal)
            ctx.setFillColor(NSColor.systemRed.cgColor)
            ctx.fillEllipse(in: badge)
            return true
        }
        image.isTemplate = false
        image.accessibilityDescription = "Proxy not running"
        return image
    }()

    private static func drawRobot(_ ctx: CGContext, color: CGColor) {
        ctx.setFillColor(color)
        ctx.setStrokeColor(color)

        let shackle = CGMutablePath()
        shackle.move(to: CGPoint(x: 5, y: 8.5))
        shackle.addLine(to: CGPoint(x: 5, y: 6))
        shackle.addArc(center: CGPoint(x: 9, y: 6), radius: 4, startAngle: .pi, endAngle: 2 * .pi, clockwise: false)
        shackle.addLine(to: CGPoint(x: 13, y: 8.5))
        ctx.addPath(shackle)
        ctx.setLineWidth(2)
        ctx.strokePath()

        // Even-odd fill: body, minus the visor, plus the eyes inside it.
        let body = CGMutablePath()
        body.addPath(RoundedRectangle(cornerRadius: 3.2, style: .continuous)
            .path(in: CGRect(x: 2, y: 7.2, width: 14, height: 9.8)).cgPath)
        body.addPath(Capsule().path(in: CGRect(x: 4.2, y: 9.4, width: 9.6, height: 4.4)).cgPath)
        for x in [7.0, 11.0] {
            body.addPath(Capsule().path(in: CGRect(x: x - 0.75, y: 10.3, width: 1.5, height: 2.6)).cgPath)
        }
        ctx.addPath(body)
        ctx.fillPath(using: .evenOdd)
    }
}

/// The 360 pt window shown from the menu bar item. Every button that opens another
/// window closes it first: the panel otherwise stays on screen above that window (it
/// never became key, so it never sees the click that would dismiss it) and can take the
/// key window status back from it.
struct MenuBarPanel: View {
    let model: AppModel
    @Environment(\.dismiss) private var dismiss
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            MenuBarHeader()
            Divider()
            if let startError = model.startError {
                Label {
                    Text(verbatim: startError)
                } icon: {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.red)
                }
                .font(.callout)
            }
            if let title = model.proxyStatus.problemTitle {
                ProxyProblemBanner(
                    title: title,
                    reason: model.proxyStatus.problemReason ?? "",
                    restart: { await model.restartProxy() },
                    dismissPanel: { dismiss() },
                    showDetails: { model.settingsPaneRequest = .proxy }
                )
            }
            let locked = model.lockedVaults
            if !locked.isEmpty {
                LockedVaultsSection(locked: locked, unlock: { model.unlockingVaultID = $0 }, dismissPanel: { dismiss() })
                Divider()
            }
            PendingSection(pending: model.pending) { id in
                dismiss()
                model.openApproval(for: id)
            }
            Divider()
            RecentSection(recent: model.recent) { id in
                dismiss()
                model.focusActivity(forRequest: id)
                ActivationPolicyController.shared.openRegularWindow { openWindow(id: "activity") }
            }
            Divider()
            MenuBarFooter(dismissPanel: { dismiss() })
        }
        .padding(12)
        .frame(width: 360)
    }
}

/// Slim header at the top of the panel: app icon and app name.
private struct MenuBarHeader: View {
    var body: some View {
        HStack(spacing: 6) {
            // The icon image carries the macOS grid margin (artwork 824/1024): draw it
            // larger than its layout frame so the artwork itself is 16 pt.
            Image(nsImage: NSApp.applicationIconImage)
                .resizable()
                .interpolation(.high)
                .frame(width: 20, height: 20)
                .frame(width: 16, height: 16)
            Text(verbatim: "Agents Secrets Manager")
                .font(.system(size: 13, weight: .semibold, design: .rounded))
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(verbatim: "Agents Secrets Manager"))
        .accessibilityAddTraits(.isHeader)
    }
}

/// Red banner while the proxy is down or not responding: headline, the cause on one
/// line (full text in the tooltip), Restart and Details… (Settings → Proxy).
private struct ProxyProblemBanner: View {
    let title: String
    let reason: String
    let restart: () async -> String?
    let dismissPanel: () -> Void
    let showDetails: () -> Void
    @Environment(\.openWindow) private var openWindow
    @State private var restarting = false
    @State private var restartError: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label {
                Text(title).font(.callout.weight(.semibold)).fixedSize(horizontal: false, vertical: true)
            } icon: {
                Image(systemName: "exclamationmark.triangle.fill")
            }
            Text(verbatim: restartError ?? reason)
                .font(.caption)
                .lineLimit(1)
                .truncationMode(.tail)
                .help(restartError ?? reason)
                .opacity(0.9)
            HStack(spacing: 8) {
                Spacer()
                if restarting { ProgressView().controlSize(.small).tint(.white) }
                BannerButton(title: "Restart") {
                    restarting = true
                    Task {
                        restartError = await restart()
                        restarting = false
                    }
                }
                .disabled(restarting)
                BannerButton(title: "Details…") {
                    dismissPanel()
                    showDetails()
                    ActivationPolicyController.shared.openRegularWindow { openWindow(id: "settings") }
                }
            }
        }
        .foregroundStyle(.white)
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.red.gradient, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        .accessibilityElement(children: .contain)
    }
}

private struct BannerButton: View {
    let title: LocalizedStringKey
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(title)
                .font(.callout.weight(.medium))
                .padding(.horizontal, 10)
                .padding(.vertical, 3)
                .background(.white.opacity(0.22), in: Capsule())
                .contentShape(Capsule())
        }
        .buttonStyle(.plain)
    }
}

/// One line per Locked Bitwarden vault; Unlock… opens the unlock sheet in the Settings window.
private struct LockedVaultsSection: View {
    let locked: [VaultItem]
    let unlock: (String) -> Void
    let dismissPanel: () -> Void
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            ForEach(locked) { vault in
                HStack(spacing: 8) {
                    Image(systemName: "lock.fill").frame(width: 18).foregroundStyle(.orange)
                    Text("\(Text(verbatim: vault.name)) is locked").lineLimit(1).truncationMode(.middle)
                    Spacer(minLength: 4)
                    Button("Unlock…") {
                        dismissPanel()
                        unlock(vault.id)
                        ActivationPolicyController.shared.openRegularWindow { openWindow(id: "settings") }
                    }
                    .controlSize(.small)
                }
                .padding(.horizontal, 4)
            }
        }
    }
}

private struct PendingSection: View {
    let pending: [PendingItem]
    let open: (String) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Pending").font(.headline)
            if pending.isEmpty {
                Text("No pending requests.").foregroundStyle(.secondary).font(.callout)
            } else {
                ForEach(pending) { item in
                    Button {
                        open(item.id)
                    } label: {
                        PendingRow(kind: item.kind, host: item.hostLabel, hostname: item.hostname, summary: item.summary, createdAt: item.createdAt)
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }
}

private struct PendingRow: View {
    let kind: RequestKind
    /// Friendly name; `hostname` follows in parentheses when it differs.
    let host: String
    let hostname: String
    let summary: String
    let createdAt: Date

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: kind.symbol).frame(width: 18).foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 1) {
                Text(verbatim: summary).lineLimit(1).truncationMode(.middle)
                Text("\(kind.title) · \(Text(verbatim: hostLine))").font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer(minLength: 4)
            Text(createdAt, style: .relative).font(.caption).foregroundStyle(.secondary).monospacedDigit()
        }
        .padding(.vertical, 3)
        .padding(.horizontal, 4)
        .contentShape(Rectangle())
    }

    private var hostLine: String {
        hostname.isEmpty || hostname == host ? host : "\(host) (\(hostname))"
    }
}

/// Resolved requests; a click shows the entry's row in the Activity Log.
private struct RecentSection: View {
    let recent: [RecentItem]
    let open: (String) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Recent").font(.headline)
            if recent.isEmpty {
                Text("Nothing resolved yet.").foregroundStyle(.secondary).font(.callout)
            } else {
                ForEach(recent.prefix(10)) { item in
                    Button {
                        open(item.id)
                    } label: {
                        RecentRow(kind: item.kind, host: item.hostLabel, summary: item.summary, outcome: item.outcome, approved: item.approved, resolvedAt: item.resolvedAt)
                    }
                    .buttonStyle(HoverRowButtonStyle())
                    .help("Show in Activity Log")
                    .accessibilityLabel(Text(verbatim: item.summary))
                    .accessibilityValue(Text(verbatim: item.outcome))
                    .accessibilityHint(Text("Shows this entry in the Activity Log"))
                }
            }
        }
    }
}

/// Plain row button with a hover highlight and the pointing-hand cursor.
private struct HoverRowButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        HoverRow(configuration: configuration)
    }

    private struct HoverRow: View {
        let configuration: ButtonStyleConfiguration
        @State private var hovering = false

        var body: some View {
            configuration.label
                .padding(.vertical, 3)
                .background(
                    RoundedRectangle(cornerRadius: 6, style: .continuous)
                        .fill(Color.primary.opacity(configuration.isPressed ? 0.14 : hovering ? 0.08 : 0))
                )
                .contentShape(Rectangle())
                .onHover { inside in
                    guard inside != hovering else { return }
                    hovering = inside
                    if inside { NSCursor.pointingHand.push() } else { NSCursor.pop() }
                }
                // The panel closes on click, before the pointer leaves the row.
                .onDisappear {
                    if hovering {
                        hovering = false
                        NSCursor.pop()
                    }
                }
        }
    }
}

private struct RecentRow: View {
    let kind: RequestKind
    let host: String
    let summary: String
    let outcome: String
    let approved: Bool
    let resolvedAt: Date

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: kind.symbol).frame(width: 18).foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 1) {
                Text(verbatim: summary).lineLimit(1).truncationMode(.middle)
                Text("\(kind.title) · \(Text(verbatim: host))").font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer(minLength: 4)
            VStack(alignment: .trailing, spacing: 1) {
                Text(verbatim: outcome)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(approved ? .green : .secondary)
                Text(resolvedAt, format: .dateTime.hour().minute()).font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, 4)
    }
}

private struct MenuBarFooter: View {
    let dismissPanel: () -> Void
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        HStack {
            Button("Settings…") {
                dismissPanel()
                ActivationPolicyController.shared.openRegularWindow { openWindow(id: "settings") }
            }
            .keyboardShortcut(",")
            Button("Show Log…") {
                dismissPanel()
                ActivationPolicyController.shared.openRegularWindow { openWindow(id: "activity") }
            }
            .keyboardShortcut("l")
            Spacer()
            Button("Quit") { NSApp.terminate(nil) }
                .keyboardShortcut("q")
        }
    }
}
