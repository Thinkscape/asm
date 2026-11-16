import AppKit
import SwiftUI

/// Floating, non-activating, borderless panel that can still take keyboard input (host
/// field, custom deny reason). The SwiftUI content draws the rounded glass background.
/// Excluded from screen sharing and screenshots.
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
            contentRect: NSRect(x: 0, y: 0, width: 410, height: 400),
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
        panel.sharingType = .none
        #if DEBUG
        // Lets screenshots capture the panel when reviewing its look in a debug build.
        if ProcessInfo.processInfo.environment["ASM_DEBUG_SHAREABLE_PANEL"] == "1" {
            panel.sharingType = .readOnly
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
