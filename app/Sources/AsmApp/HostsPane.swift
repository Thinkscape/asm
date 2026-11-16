import AppKit
import SwiftUI

struct HostsPane: View {
    let model: AppModel
    @State private var hostSelection: String?
    @State private var codeSelection: String?
    @State private var revokingHost: HostItem?
    @State private var revokingCode: PairingCodeItem?
    @State private var generating = false
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Paired hosts").font(.headline)
                Spacer()
                Button("Revoke…") {
                    revokingHost = model.hosts.first { $0.id == hostSelection }
                }
                .disabled(hostSelection == nil)
            }
            if model.hosts.isEmpty {
                EmptyStateLine(text: "No paired hosts. Run asm pair on an agent machine.")
            } else {
                Table(model.hosts, selection: $hostSelection) {
                    TableColumn("Hostname") { host in Text(verbatim: host.info.hostname) }
                    TableColumn("OS") { host in Text(verbatim: host.osLine) }
                    TableColumn("Addresses") { host in Text(verbatim: host.addressLine).help(Text(verbatim: host.addressLine)) }
                    TableColumn("Agents seen") { host in Text(verbatim: host.agentLine).help(Text(verbatim: host.agentLine)) }
                    TableColumn("Paired") { host in Text(host.pairedAt, format: .dateTime.year().month().day().hour().minute()) }
                    TableColumn("Last seen") { host in LastSeenCell(date: host.lastSeen) }
                    TableColumn("Leases") { host in Text(host.activeLeases, format: .number).monospacedDigit() }
                        .width(50)
                }
                .contextMenu(forSelectionType: String.self) { ids in
                    Button("Revoke…", role: .destructive) {
                        revokingHost = model.hosts.first { $0.id == ids.first }
                    }
                    .disabled(ids.isEmpty)
                }
                .frame(minHeight: 160)
            }

            HStack {
                Text("Pairing codes").font(.headline)
                Spacer()
                Button("Generate…") { generating = true }
                Button("Revoke…") {
                    revokingCode = model.pairingCodes.first { $0.id == codeSelection }
                }
                .disabled(codeSelection == nil)
            }
            if model.pairingCodes.isEmpty {
                Text("No pairing codes. Generate one to pair hosts without a popup.")
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, minHeight: 60)
            } else {
                Table(model.pairingCodes, selection: $codeSelection) {
                    TableColumn("Label") { code in Text(verbatim: code.label) }
                    TableColumn("Created") { code in Text(code.createdAt, format: .dateTime.year().month().day().hour().minute()) }
                    TableColumn("Expires") { code in ExpiryCell(date: code.expiresAt) }
                    TableColumn("Uses") { code in
                        Text(verbatim: code.maxUses.map { "\(code.uses) of \($0)" } ?? "\(code.uses) (unlimited)")
                            .monospacedDigit()
                    }
                    TableColumn("Status") { code in Text(verbatim: code.status) }
                }
                .frame(minHeight: 110, maxHeight: 180)
            }

            Text("Agents on this Mac should run as another user, or in a VM or container: a process of this user can read vault data.")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
        .padding()
        .sheet(isPresented: $generating) {
            PairingCodeSheet(model: model)
        }
        .confirmationDialog(
            "Revoke host “\(revokingHost?.info.hostname ?? "")”?",
            isPresented: Binding(get: { revokingHost != nil }, set: { if !$0 { revokingHost = nil } }),
            presenting: revokingHost
        ) { host in
            Button("Revoke", role: .destructive) {
                Task { error = await model.revokeHost(host.id) }
            }
        } message: { _ in
            Text("Its token stops working, its pending requests are cancelled and its leases are revoked. Raw values already delivered cannot be recalled.")
        }
        .confirmationDialog(
            "Revoke pairing code “\(revokingCode?.label ?? "")”?",
            isPresented: Binding(get: { revokingCode != nil }, set: { if !$0 { revokingCode = nil } }),
            presenting: revokingCode
        ) { code in
            Button("Revoke", role: .destructive) {
                Task { error = await model.revokePairingCode(code.id) }
            }
        } message: { _ in
            Text("Hosts already paired with it stay paired.")
        }
        .errorAlert($error)
    }
}

private struct LastSeenCell: View {
    let date: Date?

    var body: some View {
        if let date {
            Text(date, format: .relative(presentation: .named))
        } else {
            Text("never").foregroundStyle(.secondary)
        }
    }
}

struct ExpiryCell: View {
    let date: Date?

    var body: some View {
        if let date {
            Text(date, format: .dateTime.year().month().day().hour().minute())
        } else {
            Text("never").foregroundStyle(.secondary)
        }
    }
}

private struct PairingCodeSheet: View {
    let model: AppModel
    @Environment(\.dismiss) private var dismiss

    private static let expiries: [LeaseDuration] = [
        .init(seconds: 3600, title: "1 hour"), .init(seconds: 86_400, title: "24 hours"), .init(seconds: 604_800, title: "7 days"),
        .init(seconds: 2_592_000, title: "30 days"), .init(seconds: nil, title: "Never"),
    ]

    @State private var label = ""
    @State private var expiry: UInt64 = 86_400
    @State private var maxUses: UInt32 = 1
    /// `asm pair <host>:<port> <code>`, built by the core; shown once.
    @State private var command: String?
    @State private var error: String?
    @State private var working = false

    var body: some View {
        VStack(spacing: 0) {
            Form {
                if let command {
                    Section {
                        Text(verbatim: command)
                            .font(.callout.monospaced())
                            .textSelection(.enabled)
                            .fixedSize(horizontal: false, vertical: true)
                        Button("Copy command") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(command, forType: .string)
                        }
                    } header: {
                        Text("Pairing code")
                    } footer: {
                        Text("This code is shown only once. Anyone holding it can pair a host until it expires or runs out of uses.")
                    }
                } else {
                    Section {
                        TextField("Label", text: $label, prompt: Text("e.g. CI runners"))
                        Picker("Expires after", selection: $expiry) {
                            ForEach(Self.expiries) { option in
                                Text(option.title).tag(option.id)
                            }
                        }
                        Picker("Maximum uses", selection: $maxUses) {
                            Text("1").tag(UInt32(1))
                            Text("10").tag(UInt32(10))
                            Text("Unlimited").tag(UInt32(0))
                        }
                    } footer: {
                        Text("Hosts that pair with this code skip the approval popup.")
                    }
                }
                if let error {
                    Text(verbatim: error).foregroundStyle(.red)
                }
            }
            .formStyle(.grouped)
            HStack {
                Spacer()
                if command == nil {
                    Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                    Button("Generate", action: generate)
                        .keyboardShortcut(.defaultAction)
                        .disabled(label.trimmingCharacters(in: .whitespaces).isEmpty || working)
                } else {
                    Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
                }
            }
            .padding()
        }
        .frame(width: 520, height: 320)
    }

    private func generate() {
        working = true
        let label = label.trimmingCharacters(in: .whitespaces)
        let expirySecs: UInt64? = expiry == 0 ? nil : expiry
        let uses: UInt32? = maxUses == 0 ? nil : maxUses
        Task {
            do {
                command = try await model.createPairingCode(label: label, expirySecs: expirySecs, maxUses: uses)
                error = nil
            } catch {
                self.error = error.localizedDescription
            }
            working = false
        }
    }
}
