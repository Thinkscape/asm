import AppKit
import SwiftUI

/// Floating, non-activating panel that can still take keyboard input (host list,
/// custom deny reason). Excluded from screen sharing and screenshots.
final class ApprovalPanel: NSPanel {
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { false }

    /// Content-driven resizes keep the top-right corner in place.
    override func setFrame(_ frameRect: NSRect, display flag: Bool) {
        var rect = frameRect
        if isVisible, rect.origin == frame.origin, rect.size != frame.size {
            rect.origin = NSPoint(x: frame.maxX - rect.width, y: frame.maxY - rect.height)
        }
        super.setFrame(rect, display: flag)
    }
}

@MainActor
final class ApprovalPanelController {
    private unowned let model: AppModel
    private var panel: ApprovalPanel?

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
            position(panel)
        }
        panel.orderFrontRegardless()
        if takeFocus {
            panel.makeKey()
        }
    }

    /// Hides the panel; requests stay pending.
    func close() {
        panel?.orderOut(nil)
    }

    private func makePanel() -> ApprovalPanel {
        let panel = ApprovalPanel(
            contentRect: NSRect(x: 0, y: 0, width: 520, height: 400),
            styleMask: [.titled, .closable, .fullSizeContentView, .nonactivatingPanel],
            backing: .buffered,
            defer: false
        )
        panel.title = "Approval request"
        panel.titleVisibility = .hidden
        panel.titlebarAppearsTransparent = true
        panel.level = .floating
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        panel.hidesOnDeactivate = false
        panel.sharingType = .none
        panel.isReleasedWhenClosed = false
        panel.isMovableByWindowBackground = true
        // The panel follows the SwiftUI content's preferred size (height varies by request).
        let hosting = NSHostingController(rootView: ApprovalRoot(model: model))
        hosting.sizingOptions = [.preferredContentSize]
        panel.contentViewController = hosting
        return panel
    }

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
