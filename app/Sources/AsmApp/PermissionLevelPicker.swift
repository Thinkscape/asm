import AppKit
import SwiftUI

/// A native popup whose button fills the permission grid's value column, independent of its title.
struct PermissionLevelPicker: NSViewRepresentable {
    let label: String
    let options: [String]
    let requested: String?
    var allowsNone = true
    @Binding var level: String?

    @MainActor final class Coordinator: NSObject {
        var selection: Binding<String?>
        var options: [String] = []
        var requested: String?
        var allowsNone = true
        var locale: Locale?

        init(_ selection: Binding<String?>) { self.selection = selection }

        @objc func choose(_ sender: NSPopUpButton) {
            selection.wrappedValue = sender.selectedItem?.representedObject as? String
        }
    }

    func makeCoordinator() -> Coordinator { Coordinator($level) }

    func makeNSView(context: Context) -> NSPopUpButton {
        let button = NSPopUpButton(frame: .zero, pullsDown: false)
        button.target = context.coordinator
        button.action = #selector(Coordinator.choose(_:))
        return button
    }

    func updateNSView(_ button: NSPopUpButton, context: Context) {
        let coordinator = context.coordinator
        coordinator.selection = $level
        let locale = context.environment.locale
        if coordinator.options != options || coordinator.requested != requested || coordinator.locale != locale || coordinator.allowsNone != allowsNone {
            button.removeAllItems()
            if allowsNone { button.addItem(withTitle: String(localized: "None", locale: locale)) }
            for option in options {
                let title = option == requested ? String(localized: "\(option) (requested)", locale: locale) : option
                button.addItem(withTitle: title)
                button.lastItem?.representedObject = option
            }
            coordinator.options = options
            coordinator.requested = requested
            coordinator.allowsNone = allowsNone
            coordinator.locale = locale
        }
        button.setAccessibilityLabel(label)
        button.selectItem(at: level.map { button.indexOfItem(withRepresentedObject: $0) } ?? 0)
        button.isEnabled = context.environment.isEnabled
    }

    func sizeThatFits(_ proposal: ProposedViewSize, nsView: NSPopUpButton, context: Context) -> CGSize? {
        // Measure at intrinsic size, then accept the width negotiated by Grid.
        let size = nsView.intrinsicContentSize
        return CGSize(width: proposal.width.flatMap { $0.isFinite ? $0 : nil } ?? size.width, height: size.height)
    }
}
