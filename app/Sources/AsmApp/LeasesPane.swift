import SwiftUI

private enum LeaseFilter: String, CaseIterable, Identifiable {
    case active, ended, all
    var id: String { rawValue }

    var title: LocalizedStringKey {
        switch self {
        case .active: "Active"
        case .ended: "Ended"
        case .all: "All"
        }
    }

    func includes(_ status: LeaseStatus) -> Bool {
        switch self {
        case .active: status == .active
        case .ended: status != .active
        case .all: true
        }
    }
}

struct LeasesPane: View {
    let model: AppModel
    @State private var filter: LeaseFilter = .active
    @State private var search = ""
    @State private var sortOrder = [KeyPathComparator(\LeaseItem.createdAt, order: .reverse)]
    @State private var selection = Set<String>()
    @State private var visible: [LeaseItem] = []
    @State private var confirming: Set<String>?
    @State private var error: String?

    var body: some View {
        VStack(spacing: 0) {
            if visible.isEmpty {
                EmptyStateLine(text: emptyText)
            } else {
                Table(visible, selection: $selection, sortOrder: $sortOrder) {
                    TableColumn("Host", value: \.hostLabel) { lease in
                        Text(verbatim: lease.hostLabel).help(Text(verbatim: lease.hostname))
                    }
                    TableColumn("Source", value: \.source) { lease in Text(verbatim: lease.source) }
                    TableColumn("Secret", value: \.name) { lease in Text(verbatim: lease.name) }
                    TableColumn("Mode", value: \.modeLine) { lease in
                        Text(verbatim: lease.modeLine).foregroundStyle(lease.mode == .raw ? .orange : .primary)
                    }
                    TableColumn("Allowed hosts", value: \.hostsLine) { lease in
                        Text(verbatim: lease.hostsLine).help(Text(verbatim: lease.hostsLine))
                    }
                    TableColumn("Created", value: \.createdAt) { lease in
                        Text(lease.createdAt, format: .dateTime.month().day().hour().minute())
                    }
                    TableColumn("Lease expires", value: \.expiresSortKey) { lease in ExpiryCell(date: lease.expiresAt) }
                    TableColumn("Credential expires") { lease in
                        if let expiry = lease.credentialExpiresAt {
                            Text(expiry, format: .dateTime.month().day().hour().minute())
                        } else {
                            Text("—").accessibilityLabel("Not a generated credential")
                        }
                    }
                    TableColumn("Status", value: \.statusLine) { lease in
                        Text(verbatim: lease.statusLine).foregroundStyle(lease.status == .active && !lease.suspended ? .primary : .secondary)
                    }
                }
                .contextMenu(forSelectionType: String.self) { ids in
                    Button("Revoke…", role: .destructive) { revoke(ids) }
                        .disabled(activeIDs(in: ids).isEmpty)
                }
            }
        }
        .searchable(text: $search, prompt: Text("Host, source or secret"))
        .toolbar {
            ToolbarItemGroup {
                Picker("Show", selection: $filter) {
                    ForEach(LeaseFilter.allCases) { filter in
                        Text(filter.title).tag(filter)
                    }
                }
                .pickerStyle(.segmented)
                Button {
                    revoke(selection)
                } label: {
                    Label("Revoke", systemImage: "xmark.circle")
                }
                .disabled(activeIDs(in: selection).isEmpty)
            }
        }
        .inspector(isPresented: Binding(
            get: { selectedLease != nil },
            set: { if !$0 { selection = [] } }
        )) {
            if let selectedLease {
                LeaseDetail(lease: selectedLease)
                    .inspectorColumnWidth(min: 260, ideal: 320, max: 480)
            }
        }
        .confirmationDialog(
            "Revoke \(confirming?.count ?? 0) leases?",
            isPresented: Binding(get: { confirming != nil }, set: { if !$0 { confirming = nil } }),
            presenting: confirming
        ) { ids in
            Button("Revoke", role: .destructive) { perform(ids) }
        } message: { _ in
            Text("Their sentinels stop working at once. ASM attempts to revoke generated tokens, but raw copies may remain usable until provider expiry if revocation fails. Static raw values cannot be recalled.")
        }
        .errorAlert($error)
        .onAppear(perform: recompute)
        .onChange(of: model.leases) { recompute() }
        .onChange(of: filter) { recompute() }
        .onChange(of: search) { recompute() }
        .onChange(of: sortOrder) { recompute() }
        .onChange(of: model.leaseFocus, initial: true) { _, focus in
            guard let focus else { return }
            filter = .all
            search = focus.search
            recompute()
            if visible.contains(where: { $0.id == focus.leaseID }) {
                selection = [focus.leaseID]
            }
            model.leaseFocus = nil
        }
    }

    private var selectedLease: LeaseItem? {
        guard selection.count == 1, let id = selection.first else { return nil }
        return model.leases.first { $0.id == id }
    }

    private var emptyText: LocalizedStringKey {
        if !search.isEmpty { return "No leases match the search." }
        switch filter {
        case .active: return "No active leases."
        case .ended: return "No ended leases."
        case .all: return "No leases yet."
        }
    }

    private func recompute() {
        let query = search.trimmingCharacters(in: .whitespaces)
        visible = model.leases
            .filter { lease in
                filter.includes(lease.status) && (query.isEmpty
                    || lease.hostLabel.localizedCaseInsensitiveContains(query)
                    || lease.hostname.localizedCaseInsensitiveContains(query)
                    || lease.source.localizedCaseInsensitiveContains(query)
                    || lease.name.localizedCaseInsensitiveContains(query))
            }
            .sorted(using: sortOrder)
        selection.formIntersection(visible.map(\.id))
    }

    private func activeIDs(in ids: Set<String>) -> Set<String> {
        Set(model.leases.filter { ids.contains($0.id) && $0.status == .active }.map(\.id))
    }

    private func revoke(_ ids: Set<String>) {
        let active = activeIDs(in: ids)
        guard !active.isEmpty else { return }
        if active.count > 1 {
            confirming = active
        } else {
            perform(active)
        }
    }

    private func perform(_ ids: Set<String>) {
        Task { error = await model.revokeLeases(ids) }
    }
}

private struct LeaseDetail: View {
    let lease: LeaseItem

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Text(verbatim: lease.name).font(.headline).textSelection(.enabled)
                LabeledContent("Source", value: lease.source)
                LabeledContent("Host", value: lease.hostLabel)
                LabeledContent("Delivery", value: lease.modeLine)
                LabeledContent("Status", value: lease.status.rawValue)
                if let reason = lease.suspensionReason, lease.suspended {
                    Label(reason, systemImage: "pause.circle").fixedSize(horizontal: false, vertical: true)
                }
                LabeledContent("Authorized fields", value: lease.fields.formatted())
                LabeledContent("Allowed hosts", value: lease.hostsLine)
                LabeledContent("Approved") { Text(lease.createdAt, format: .dateTime.year().month().day().hour().minute()) }
                LabeledContent("Lease expires") { ExpiryCell(date: lease.expiresAt) }
                if let generation = lease.generation {
                    Divider()
                    Text("GitHub App").font(.subheadline.weight(.semibold)).accessibilityAddTraits(.isHeader)
                    Text(lease.generatorName ?? lease.source).font(.headline)
                    LabeledContent("Revision", value: String(generation.generatorRevision))
                    LabeledContent("Generator ID", value: generation.generatorID).textSelection(.enabled)
                    GithubGrantSummary(grant: generation.grant.github)
                    if let expiry = lease.credentialExpiresAt {
                        LabeledContent("Credential expires") {
                            Text(expiry, format: .dateTime.year().month().day().hour().minute().second())
                        }
                    } else {
                        Text("No live credential has been issued.")
                    }
                    if let version = lease.credentialVersion { LabeledContent("Credential version", value: String(version)) }
                    Text("Credential expiry and lease expiry are independent. Run asm get again to renew a token within this authorization; renewal never extends the lease.")
                        .font(.callout).foregroundStyle(.secondary)
                    if lease.mode == .raw {
                        Label("Delivered tokens may remain usable until GitHub expiry after failed revocation or a manager crash.", systemImage: "exclamationmark.triangle")
                            .font(.callout).fixedSize(horizontal: false, vertical: true)
                    }
                } else if lease.mode == .raw {
                    Text("Static raw values already delivered cannot be recalled.").font(.callout)
                }
                Divider()
                LabeledContent("Lease ID", value: lease.id).font(.caption.monospaced()).textSelection(.enabled)
            }
            .font(.callout)
            .padding()
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

private struct GithubGrantSummary: View {
    let grant: GithubGrantItem

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            LabeledContent("Installation", value: String(grant.installationID))
            Text("Approved repositories").font(.subheadline.weight(.semibold)).accessibilityAddTraits(.isHeader)
            ForEach(grant.repositories) { repository in
                VStack(alignment: .leading, spacing: 2) {
                    Text(verbatim: repository.fullName)
                    Text("Repository ID \(repository.id)").font(.caption).foregroundStyle(.secondary)
                }
                .accessibilityElement(children: .combine)
            }
            Text("Approved permissions").font(.subheadline.weight(.semibold)).accessibilityAddTraits(.isHeader)
            ForEach(grant.permissions) { permission in
                LabeledContent(permission.scopeLabel, value: permission.level.rawValue)
            }
            Text("Repository selection does not restrict organization, account, or enterprise permissions.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }
}
