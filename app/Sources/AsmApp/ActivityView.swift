import AppKit
import SwiftUI

/// Toolbar filter of the Activity Log.
private enum ActivityTab: String, CaseIterable, Identifiable {
    case all, requests, leases, proxy, pairing, vaults

    var id: String { rawValue }

    var title: String {
        switch self {
        case .all: "All"
        default: ActivityCategory(rawValue: rawValue)?.title ?? rawValue
        }
    }

    var categories: [String] {
        self == .all ? [] : [rawValue]
    }
}

/// The Activity Log window: newest first, live, paged with "Load older".
struct ActivityView: View {
    let model: AppModel
    @Environment(\.openWindow) private var openWindow

    private static let pageSize: UInt32 = 200

    @State private var tab: ActivityTab = .all
    /// "" = all hosts.
    @State private var hostID = ""
    @State private var search = ""
    @State private var rows: [ActivityItem] = []
    @State private var selection: ActivityItem.ID?
    @State private var hasMore = false
    @State private var loaded = false
    @State private var loadingOlder = false
    @State private var error: String?

    private var query: ActivityQueryItem {
        ActivityQueryItem(
            categories: tab.categories,
            hostID: hostID.isEmpty ? nil : hostID,
            search: search.trimmingCharacters(in: .whitespacesAndNewlines),
            beforeID: nil,
            limit: Self.pageSize
        )
    }

    private var selectedRow: ActivityItem? {
        rows.first { $0.id == selection }
    }

    var body: some View {
        VStack(spacing: 0) {
            if rows.isEmpty {
                EmptyStateLine(text: emptyText)
            } else {
                table
                Divider()
                footer
            }
        }
        .frame(minWidth: 760, minHeight: 420)
        .background(RegularWindowMarker())
        .searchable(text: $search, prompt: Text("Summary, secret or host"))
        .toolbar {
            ToolbarItemGroup {
                Picker("Category", selection: $tab) {
                    ForEach(ActivityTab.allCases) { tab in
                        Text(tab.title).tag(tab)
                    }
                }
                .pickerStyle(.segmented)
                Picker("Host", selection: $hostID) {
                    Text("All hosts").tag("")
                    if !hostID.isEmpty, !model.hosts.contains(where: { $0.id == hostID }) {
                        Text("Revoked host").tag(hostID)
                    }
                    ForEach(model.hosts) { host in
                        Text(verbatim: host.name).tag(host.id)
                    }
                }
                .pickerStyle(.menu)
                .frame(minWidth: 140)
            }
        }
        .inspector(isPresented: Binding(
            get: { selectedRow != nil },
            set: { if !$0 { selection = nil } }
        )) {
            if let row = selectedRow {
                ActivityDetail(row: row, hostLabel: hostLabel(row))
                    .inspectorColumnWidth(min: 260, ideal: 340, max: 520)
            }
        }
        .errorAlert($error)
        .task(id: query) { await reload() }
        .onChange(of: model.activityRevision) {
            Task { await fetchNewer() }
        }
    }

    private var table: some View {
        Table(rows, selection: $selection) {
            TableColumn("Time") { row in
                TimelineView(.everyMinute) { context in
                    Text(verbatim: Self.timeText(row.at, now: context.date))
                        .help(Text(verbatim: row.at.formatted(.dateTime.year().month().day().hour().minute().second())))
                }
            }
            .width(min: 90, ideal: 120, max: 170)
            TableColumn("Category") { row in
                if let category = row.knownCategory {
                    Label(category.title, systemImage: category.symbol)
                } else {
                    Text(verbatim: row.category)
                }
            }
            .width(min: 90, ideal: 110, max: 140)
            TableColumn("Host") { row in
                Text(verbatim: hostLabel(row))
            }
            .width(min: 80, ideal: 130, max: 220)
            TableColumn("Secret") { row in
                Text(verbatim: row.secret ?? "")
            }
            .width(min: 80, ideal: 140, max: 260)
            TableColumn("Summary") { row in
                Text(verbatim: row.summary).help(Text(verbatim: row.summary))
            }
        }
        .contextMenu(forSelectionType: ActivityItem.ID.self) { ids in
            let chosen = rows.filter { ids.contains($0.id) }
            Button("Copy Summary") {
                copy(chosen.map(\.summary).joined(separator: "\n"))
            }
            .disabled(chosen.isEmpty)
            if chosen.count == 1, let row = chosen.first, let leaseID = row.leaseID {
                Button("Show Lease") { showLease(leaseID, secret: row.secret ?? "") }
            }
        }
    }

    private var footer: some View {
        HStack {
            Text("\(rows.count) entries").foregroundStyle(.secondary)
            Spacer()
            if hasMore {
                Button {
                    Task { await loadOlder() }
                } label: {
                    if loadingOlder {
                        ProgressView().controlSize(.small)
                    } else {
                        Text("Load older")
                    }
                }
                .disabled(loadingOlder)
            }
        }
        .font(.callout)
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
    }

    private var emptyText: LocalizedStringKey {
        if !loaded { return "" }
        let filtered = tab != .all || !hostID.isEmpty || !query.search.isEmpty
        return filtered ? "No matching activity." : "No activity yet."
    }

    /// Current friendly name (follows renames while the window is open).
    private func hostLabel(_ row: ActivityItem) -> String {
        guard let id = row.hostID else { return "" }
        return model.hosts.first { $0.id == id }?.name ?? row.hostLabel
    }

    /// Relative within 24 hours, else date and time.
    static func timeText(_ date: Date, now: Date) -> String {
        if now.timeIntervalSince(date) < 86_400 {
            if now.timeIntervalSince(date) < 60 { return String(localized: "just now") }
            return date.formatted(.relative(presentation: .named, unitsStyle: .abbreviated))
        }
        return date.formatted(date: .abbreviated, time: .shortened)
    }

    // MARK: Loading

    private func reload() async {
        let q = query
        do {
            let page = try await model.listActivity(q)
            guard q == query else { return }
            rows = page
            hasMore = page.count == Int(Self.pageSize)
            if let selection, !page.contains(where: { $0.id == selection }) {
                self.selection = nil
            }
        } catch {
            self.error = error.localizedDescription
        }
        loaded = true
    }

    /// New rows go on top; the selection and the loaded older pages stay.
    private func fetchNewer() async {
        guard loaded else { return }
        let q = query
        guard let page = try? await model.listActivity(q), q == query else { return }
        guard let top = rows.first?.id else {
            rows = page
            hasMore = page.count == Int(Self.pageSize)
            return
        }
        let newer = page.filter { $0.id > top }
        if newer.count == Int(Self.pageSize) {
            // More arrived than one page: start over from the newest page.
            rows = page
            hasMore = true
        } else if !newer.isEmpty {
            rows.insert(contentsOf: newer, at: 0)
        }
    }

    private func loadOlder() async {
        guard let last = rows.last?.id, !loadingOlder else { return }
        loadingOlder = true
        defer { loadingOlder = false }
        var q = query
        q.beforeID = last
        do {
            let page = try await model.listActivity(q)
            guard q.categories == query.categories, q.hostID == query.hostID, q.search == query.search,
                  rows.last?.id == last else { return }
            rows.append(contentsOf: page)
            hasMore = page.count == Int(Self.pageSize)
        } catch {
            self.error = error.localizedDescription
        }
    }

    // MARK: Actions

    private func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }

    private func showLease(_ leaseID: String, secret: String) {
        model.showLease(leaseID, secret: secret)
        openWindow(id: "settings")
        NSApp.activate()
    }
}

/// Inspector: the selected row and its detail (pretty-printed JSON), with Copy.
private struct ActivityDetail: View {
    let row: ActivityItem
    let hostLabel: String

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Text(verbatim: row.summary)
                    .font(.headline)
                    .textSelection(.enabled)
                Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 4) {
                    GridRow {
                        Text("Time").foregroundStyle(.secondary)
                        Text(verbatim: row.at.formatted(.dateTime.year().month().day().hour().minute().second()))
                    }
                    GridRow {
                        Text("Category").foregroundStyle(.secondary)
                        Text(verbatim: "\(row.knownCategory?.title ?? row.category) · \(row.kind)")
                    }
                    if !hostLabel.isEmpty {
                        GridRow {
                            Text("Host").foregroundStyle(.secondary)
                            Text(verbatim: hostLabel)
                        }
                    }
                    if let secret = row.secret {
                        GridRow {
                            Text("Secret").foregroundStyle(.secondary)
                            Text(verbatim: secret)
                        }
                    }
                }
                .font(.callout)
                if let detail = row.prettyDetail {
                    HStack {
                        Text("Detail").font(.subheadline.weight(.semibold))
                        Spacer()
                        Button {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(detail, forType: .string)
                        } label: {
                            Label("Copy", systemImage: "doc.on.doc")
                        }
                        .controlSize(.small)
                    }
                    Text(verbatim: detail)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(8)
                        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 6))
                }
            }
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}
