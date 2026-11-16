import AppKit
import SwiftUI

struct MenuBarLabel: View {
    let pendingCount: Int

    var body: some View {
        if pendingCount > 0 {
            Text("\(Image(systemName: "key.fill")) \(pendingCount)")
        } else {
            Image(systemName: "key.fill")
        }
    }
}

/// The 360 pt window shown from the menu bar item. Every button that opens another
/// window closes it first: the panel otherwise stays on screen above that window (it
/// never became key, so it never sees the click that would dismiss it) and can take the
/// key window status back from it.
struct MenuBarPanel: View {
    let model: AppModel
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            if let startError = model.startError {
                Label {
                    Text(verbatim: startError)
                } icon: {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.red)
                }
                .font(.callout)
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
            RecentSection(recent: model.recent)
            Divider()
            MenuBarFooter(dismissPanel: { dismiss() })
        }
        .padding(12)
        .frame(width: 360)
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

private struct RecentSection: View {
    let recent: [RecentItem]

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Recent").font(.headline)
            if recent.isEmpty {
                Text("Nothing resolved yet.").foregroundStyle(.secondary).font(.callout)
            } else {
                ForEach(recent.prefix(10)) { item in
                    RecentRow(kind: item.kind, host: item.hostLabel, summary: item.summary, outcome: item.outcome, approved: item.approved, resolvedAt: item.resolvedAt)
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
