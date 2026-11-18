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
            confirming?.count == 1 ? "End this lease?" : "End \(confirming?.count ?? 0) leases?",
            isPresented: Binding(get: { confirming != nil }, set: { if !$0 { confirming = nil } }),
            presenting: confirming
        ) { ids in
            Button("End lease access", role: .destructive) { perform(ids) }
        } message: { ids in
            revokeMessage(for: ids)
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
        if active.count > 1 || model.leases.contains(where: { active.contains($0.id) && $0.isGoogleGenerated }) {
            confirming = active
        } else {
            perform(active)
        }
    }

    private func revokeMessage(for ids: Set<String>) -> Text {
        let googleCount = model.leases.lazy.filter { ids.contains($0.id) && $0.isGoogleGenerated }.count
        if googleCount == ids.count {
            return Text(GcloudTokenWarning.text)
        }
        if googleCount > 0 {
            return Text("Ending these leases stops ASM delivery. Google access tokens cannot be individually revoked; copies remain usable until credential expiry. ASM attempts to revoke GitHub tokens, and static raw values cannot be recalled.")
        }
        return Text("Their sentinels stop working at once. ASM attempts to revoke GitHub tokens, but raw copies may remain usable until provider expiry if revocation fails. Static raw values cannot be recalled.")
    }

    private func perform(_ ids: Set<String>) {
        Task { error = await model.revokeLeases(ids) }
    }
}

private extension LeaseItem {
    var isGoogleGenerated: Bool {
        switch generation?.grant {
        case .gcloud?, .gcloudAccess?: true
        case .githubApp?, nil: false
        }
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
                    Text(lease.isGoogleGenerated ? "Google Cloud" : "GitHub App")
                        .font(.subheadline.weight(.semibold)).accessibilityAddTraits(.isHeader)
                    Text(lease.generatorName ?? lease.source).font(.headline)
                    LabeledContent("Revision", value: String(generation.generatorRevision))
                    LabeledContent("Generator ID", value: generation.generatorID).textSelection(.enabled)
                    switch generation.grant {
                    case let .githubApp(grant): GithubGrantSummary(grant: grant)
                    case let .gcloud(grant): GcloudGrantSummary(grant: grant)
                    case let .gcloudAccess(.issued(access, uniqueID, email)):
                        GcloudManagedGrantSummary(access: access, uniqueID: uniqueID, email: email)
                    case .gcloudAccess:
                        Text("No issued Google access grant is recorded for this lease.")
                            .foregroundStyle(.secondary)
                    }
                    if let expiry = lease.credentialExpiresAt {
                        LabeledContent("Credential expires") {
                            Text(expiry, format: .dateTime.year().month().day().hour().minute().second())
                        }
                    } else if lease.isGoogleGenerated {
                        Text("ASM is not tracking a live Google credential for this lease.")
                    } else {
                        Text("No live credential has been issued.")
                    }
                    if let version = lease.credentialVersion { LabeledContent("Credential version", value: String(version)) }
                    Text("Credential expiry and lease expiry are independent. Run asm get again to renew a token within this authorization; renewal never extends the lease.")
                        .font(.callout).foregroundStyle(.secondary)
                    if lease.isGoogleGenerated {
                        Label(GcloudTokenWarning.text, systemImage: "exclamationmark.triangle")
                            .font(.callout).fixedSize(horizontal: false, vertical: true)
                    } else if lease.mode == .raw {
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

private struct GcloudGrantSummary: View {
    let grant: GcloudGrantItem

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            GcloudServiceAccountSummary(email: grant.serviceAccountEmail, uniqueID: grant.serviceAccountUniqueID)
            LabeledContent("Approved issuance quota project") {
                if let projectID = grant.projectID {
                    Text(projectID).monospaced().textSelection(.enabled)
                } else {
                    Text("Not recorded on this lease").foregroundStyle(.secondary)
                }
            }
            Text(GcloudIAMWarning.issuanceProjectText).font(.caption).foregroundStyle(.secondary)
            Text("Approved OAuth scopes").font(.subheadline.weight(.semibold)).accessibilityAddTraits(.isHeader)
            GcloudScopeURIList(scopes: grant.scopes)
            if grant.scopes.contains(where: GcloudIAMWarning.isCrossService) {
                Label(GcloudIAMWarning.crossServiceText, systemImage: "exclamationmark.triangle")
                    .fixedSize(horizontal: false, vertical: true)
            }
            Text(GcloudIAMWarning.text)
            Text(GcloudTokenWarning.clientUsage)
        }
    }
}

private struct GcloudManagedGrantSummary: View {
    let access: GcloudAccessRequestItem
    let uniqueID: String
    let email: String

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            GcloudServiceAccountSummary(email: email, uniqueID: uniqueID)
            GcloudAccessClaimsSummary(heading: "Approved permissions", access: access)
            Text(GcloudManagedIAMWarning.text)
            Text("Ending this lease does not remove the service account or its IAM bindings.")
            Text(GcloudTokenWarning.clientUsage)
        }
    }
}
