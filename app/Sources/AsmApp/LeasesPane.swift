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
                    TableColumn("Expires", value: \.expiresSortKey) { lease in ExpiryCell(date: lease.expiresAt) }
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
        .confirmationDialog(
            "Revoke \(confirming?.count ?? 0) leases?",
            isPresented: Binding(get: { confirming != nil }, set: { if !$0 { confirming = nil } }),
            presenting: confirming
        ) { ids in
            Button("Revoke", role: .destructive) { perform(ids) }
        } message: { _ in
            Text("Their sentinels stop working at once. Raw values already delivered cannot be recalled.")
        }
        .errorAlert($error)
        .onAppear(perform: recompute)
        .onChange(of: model.leases) { recompute() }
        .onChange(of: filter) { recompute() }
        .onChange(of: search) { recompute() }
        .onChange(of: sortOrder) { recompute() }
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
