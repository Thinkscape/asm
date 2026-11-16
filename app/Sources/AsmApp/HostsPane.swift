import AppKit
import SwiftUI

struct HostsPane: View {
    let model: AppModel
    @State private var hostSelection: String?
    @State private var codeSelection: String?
    @State private var revokingHost: HostItem?
    @State private var renamingHost: HostItem?
    @State private var revokingCode: PairingCodeItem?
    @State private var generating = false
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Paired hosts").font(.headline)
                Spacer()
                Button("Rename…") {
                    renamingHost = model.hosts.first { $0.id == hostSelection }
                }
                .disabled(hostSelection == nil)
                Button("Revoke…") {
                    revokingHost = model.hosts.first { $0.id == hostSelection }
                }
                .disabled(hostSelection == nil)
            }
            if model.hosts.isEmpty {
                EmptyStateLine(text: "No paired hosts. Run asm pair on an agent machine.")
            } else {
                Table(model.hosts, selection: $hostSelection) {
                    TableColumn("Name") { host in Text(verbatim: host.name) }
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
                    Button("Rename…") {
                        renamingHost = model.hosts.first { $0.id == ids.first }
                    }
                    .disabled(ids.count != 1)
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
                    TableColumn("Allowed networks") { code in
                        Text(verbatim: code.networksLine)
                            .foregroundStyle(code.allowedNetworks.isEmpty ? .secondary : .primary)
                            .help(Text(verbatim: code.networksLine))
                    }
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
        .sheet(item: $renamingHost) { host in
            RenameHostSheet(model: model, host: host)
        }
        .confirmationDialog(
            "Revoke host “\(revokingHost?.name ?? "")”?",
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

private struct RenameHostSheet: View {
    let model: AppModel
    let host: HostItem
    @Environment(\.dismiss) private var dismiss
    @State private var name: String
    @State private var error: String?
    @State private var working = false

    init(model: AppModel, host: HostItem) {
        self.model = model
        self.host = host
        _name = State(initialValue: host.name)
    }

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Section {
                    TextField(text: $name, prompt: Text(verbatim: host.info.hostname)) {
                        Text("Friendly name")
                    }
                    .onSubmit(save)
                } footer: {
                    Text("Shown wherever this host appears. Leave empty to use its hostname, \(Text(verbatim: host.info.hostname)). At most 64 characters.")
                }
                if let error {
                    Text(verbatim: error).foregroundStyle(.red)
                }
            }
            .formStyle(.grouped)
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Rename", action: save)
                    .keyboardShortcut(.defaultAction)
                    .disabled(working)
            }
            .padding()
        }
        .frame(width: 420, height: 200)
    }

    private func save() {
        guard !working else { return }
        working = true
        Task {
            if let failure = await model.renameHost(host.id, name: name) {
                error = failure
            } else {
                dismiss()
            }
            working = false
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
    /// Comma- or newline-separated CIDR ranges or addresses; empty = any address.
    @State private var networks = ""
    @State private var subnets: [String] = []
    /// `asm pair <host>:<port> <code>`, built by the core; shown once.
    @State private var command: String?
    @State private var error: String?
    @State private var working = false

    private var networkEntries: [String] {
        networks
            .split(whereSeparator: { $0 == "," || $0.isNewline })
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    /// The core's message for the first invalid entry, if any.
    private var networkError: String? {
        for entry in networkEntries {
            if case let .failure(failure) = CoreBridge.checkNetwork(entry) { return failure.message }
        }
        return nil
    }

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
                    Section {
                        TextField("Allowed networks", text: $networks, prompt: Text(verbatim: "10.0.0.0/8, 100.64.0.0/10"), axis: .vertical)
                            .lineLimit(1...4)
                        let suggestions = subnets.filter { !networkEntries.contains($0) }
                        if !suggestions.isEmpty {
                            LabeledContent("Suggestions") {
                                Menu("Add from this Mac") {
                                    ForEach(suggestions, id: \.self) { subnet in
                                        Button { addNetwork(subnet) } label: { Text(verbatim: subnet) }
                                    }
                                }
                                .fixedSize()
                            }
                        }
                        if let networkError {
                            Text(verbatim: networkError).foregroundStyle(.red).font(.callout)
                        }
                    } footer: {
                        Text("CIDR ranges or addresses, separated by commas or new lines. Pairing succeeds only from an address in one of them, as seen by this Mac. Leave empty to allow any address.")
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
                        .disabled(label.trimmingCharacters(in: .whitespaces).isEmpty || networkError != nil || working)
                } else {
                    Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
                }
            }
            .padding()
        }
        .frame(width: 520, height: command == nil ? 440 : 320)
        .task {
            subnets = await Task.detached(priority: .utility) { CoreBridge.subnetSuggestions() }.value
        }
    }

    private func addNetwork(_ subnet: String) {
        let trimmed = networks.trimmingCharacters(in: .whitespacesAndNewlines)
        networks = trimmed.isEmpty ? subnet : "\(trimmed), \(subnet)"
    }

    private func generate() {
        working = true
        let label = label.trimmingCharacters(in: .whitespaces)
        let expirySecs: UInt64? = expiry == 0 ? nil : expiry
        let uses: UInt32? = maxUses == 0 ? nil : maxUses
        let networks = networkEntries
        Task {
            do {
                command = try await model.createPairingCode(label: label, expirySecs: expirySecs, maxUses: uses, networks: networks)
                error = nil
            } catch {
                self.error = error.localizedDescription
            }
            working = false
        }
    }
}
