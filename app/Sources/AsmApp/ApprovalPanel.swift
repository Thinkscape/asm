import AppKit
import SwiftUI

/// Floating, non-activating, borderless panel that can still take keyboard input (host
/// field, custom deny reason). The SwiftUI content draws the rounded glass background.
/// Token permission requests can be captured; pairing and secret-edit panels stay private.
final class ApprovalPanel: NSPanel {
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { false }

    /// A height animation started by `setFrame` is running.
    private var animatingResize = false

    /// Content-driven resizes keep the top-right corner in place and animate. SwiftUI
    /// must not animate the window itself (`withAnimation` around a size change): its
    /// animated window resize re-enters AppKit layout and crashes.
    override func setFrame(_ frameRect: NSRect, display flag: Bool) {
        var rect = frameRect
        guard isVisible, rect.origin == frame.origin, rect.size != frame.size else {
            super.setFrame(rect, display: flag)
            invalidateShadow()
            return
        }
        rect.origin = NSPoint(x: frame.maxX - rect.width, y: frame.maxY - rect.height)
        if animatingResize || NSWorkspace.shared.accessibilityDisplayShouldReduceMotion {
            super.setFrame(rect, display: flag)
            invalidateShadow()
            return
        }
        animatingResize = true
        NSAnimationContext.runAnimationGroup { context in
            context.duration = 0.18
            context.timingFunction = CAMediaTimingFunction(name: .easeInEaseOut)
            animator().setFrame(rect, display: true)
        } completionHandler: { [weak self] in
            MainActor.assumeIsolated {
                guard let self else { return }
                self.animatingResize = false
                self.invalidateShadow()
                // The content may have changed size again while the animation ran.
                if let size = self.contentViewController?.preferredContentSize, size.height > 0, size != self.frame.size {
                    self.setContentSize(size)
                }
            }
        }
    }
}

@MainActor
final class ApprovalPanelController {
    private unowned let model: AppModel
    private var panel: ApprovalPanel?
    #if DEBUG
    private var snapshotSignal: DispatchSourceSignal?
    #endif

    init(model: AppModel) {
        self.model = model
    }

    /// Shows the panel at the top right of the screen under the pointer. A newly
    /// arrived request does not take keyboard focus (keystrokes meant for another
    /// app must not reach the panel); opening it from the menu bar does.
    func present(takeFocus: Bool) {
        let panel = panel ?? makePanel()
        self.panel = panel
        if !panel.isVisible {
            model.approvalPanelWillOpen()
            position(panel)
        }
        panel.orderFrontRegardless()
        if takeFocus {
            panel.makeKey()
        }
    }

    /// Use a fresh backing window at privacy boundaries. Never make a window
    /// containing old pairing codes or secret values shareable during a redraw.
    func prepare(for request: PendingItem?) -> Bool {
        guard let panel, panel.sharingType != Self.sharingType(for: request) else { return false }
        let visible = panel.isVisible
        panel.orderOut(nil)
        panel.contentViewController = nil
        self.panel = nil
        return visible
    }

    private static func sharingType(for request: PendingItem?) -> NSWindow.SharingType {
        guard case let .get(detail)? = request?.detail, detail.isGenerated else { return .none }
        return .readOnly
    }

    /// Hides the panel; requests stay pending.
    func close() {
        panel?.orderOut(nil)
    }

    private func makePanel() -> ApprovalPanel {
        let panel = ApprovalPanel(
            contentRect: NSRect(x: 0, y: 0, width: 400, height: 400),
            styleMask: [.borderless, .nonactivatingPanel],
            backing: .buffered,
            defer: false
        )
        panel.title = "Approval request"
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = true
        panel.level = .floating
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        panel.hidesOnDeactivate = false
        panel.sharingType = Self.sharingType(for: model.shownRequest)
        #if DEBUG
        // Optional self-rendering of capturable token panels for debug layout checks.
        if ProcessInfo.processInfo.environment["ASM_DEBUG_SHAREABLE_PANEL"] == "1" {
            installSnapshotSignal()
        }
        #endif
        panel.isReleasedWhenClosed = false
        panel.isMovableByWindowBackground = true
        // The panel follows the SwiftUI content's preferred size (height varies by request).
        let hosting = NSHostingController(rootView: ApprovalRoot(model: model) { [weak self] in self?.close() })
        hosting.sizingOptions = [.preferredContentSize]
        hosting.view.wantsLayer = true
        hosting.view.layer?.backgroundColor = .clear
        panel.contentViewController = hosting
        return panel
    }

    #if DEBUG
    /// `kill -USR1 <pid>` writes the panel's own rendering to
    /// `$TMPDIR/asm-panel-<time>.png`, for reviewing its look where screen capture is
    /// not permitted. Open menus and the glass backdrop are not part of the image.
    private func installSnapshotSignal() {
        guard snapshotSignal == nil else { return }
        signal(SIGUSR1, SIG_IGN)
        let source = DispatchSource.makeSignalSource(signal: SIGUSR1, queue: .main)
        source.setEventHandler { [weak self] in
            MainActor.assumeIsolated { self?.writeSnapshot() }
        }
        source.resume()
        snapshotSignal = source
    }

    private func writeSnapshot() {
        guard let panel, panel.sharingType == .readOnly, let view = panel.contentView,
              let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { return }
        view.effectiveAppearance.performAsCurrentDrawingAppearance {
            view.cacheDisplay(in: view.bounds, to: rep)
        }
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("asm-panel-\(Int(Date().timeIntervalSince1970 * 1000)).png")
        try? rep.representation(using: .png, properties: [:])?.write(to: url)
        NSLog("asm debug snapshot: %@", url.path)
    }
    #endif

    private func position(_ panel: NSPanel) {
        let mouse = NSEvent.mouseLocation
        let screen = NSScreen.screens.first { NSMouseInRect(mouse, $0.frame, false) } ?? NSScreen.main
        guard let visible = screen?.visibleFrame else { return }
        // The hosting controller sizes the panel lazily; settle the content size first so
        // the top-right placement uses the real width (otherwise it lands off screen).
        if let view = panel.contentViewController?.view {
            view.layoutSubtreeIfNeeded()
            let fitting = view.fittingSize
            if fitting.width > 0, fitting.height > 0 {
                panel.setContentSize(fitting)
            }
        }
        let size = panel.frame.size
        let margin: CGFloat = 16
        panel.setFrameOrigin(NSPoint(x: visible.maxX - size.width - margin, y: visible.maxY - size.height - margin))
    }
}

/// Open `asm login` sign-in browsers, at the top of the approval panel: what each is
/// doing, "Hand over session" (the agent receives the site's session) and "Cancel".
struct BrokerSessionList: View {
    let model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionLabel("Sign-in browsers")
            ForEach(model.brokerSessions) { session in
                BrokerSessionRow(session: session, error: model.brokerErrors[session.id]) {
                    model.handOverBrokerSession(session.id)
                } cancel: {
                    model.cancelBrokerSession(session.id)
                }
            }
        }
    }
}

private struct BrokerSessionRow: View {
    let session: BrokerSessionItem
    let error: String?
    let handOver: () -> Void
    let cancel: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline) {
                Text(verbatim: session.hostLabel).font(.system(size: 13, weight: .semibold))
                Spacer(minLength: 8)
                Text(session.startedAt, style: .relative)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Text(verbatim: session.url)
                .font(.system(size: 12).monospaced())
                .lineLimit(1)
                .truncationMode(.middle)
                .textSelection(.enabled)
            Text(verbatim: session.status)
                .font(.callout)
                .foregroundStyle(session.status.hasPrefix("paused") ? AnyShapeStyle(.orange) : AnyShapeStyle(.secondary))
                .fixedSize(horizontal: false, vertical: true)
            if let error {
                Label {
                    Text(verbatim: error).fixedSize(horizontal: false, vertical: true)
                } icon: {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.red)
                }
                .font(.callout)
            }
            HStack(spacing: 8) {
                Spacer(minLength: 0)
                Button("Cancel", action: cancel)
                Button("Hand over session", action: handOver)
                    .buttonStyle(.borderedProminent)
            }
            .controlSize(.large)
        }
        .padding(12)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
    }
}
