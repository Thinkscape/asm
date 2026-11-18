import Foundation
import SwiftUI

struct GcloudOwnedAccountsPane: View {
    let model: AppModel
    @State private var rows: [GcloudOwnedAccountItem] = []
    @State private var selection: Int64?
    @State private var presentation: GcloudAccountPresentation?
    @State private var refreshCount = 0
    @State private var loaded: LoadRequest?
    @State private var loadError: String?
    @State private var deleteError: String?
    @State private var deletingID: Int64?

    private struct LoadRequest: Equatable {
        let revision: Int
        let refreshCount: Int
    }

    private var request: LoadRequest {
        LoadRequest(revision: model.gcloudOwnedAccountsRevision, refreshCount: refreshCount)
    }

    private var isCurrent: Bool { loaded == request }
    private var selected: GcloudOwnedAccountItem? { rows.first { $0.id == selection } }

    var body: some View {
        VStack(spacing: 0) {
            GcloudOwnedAccountsHeader { refreshCount &+= 1 }
            Divider()
            if rows.isEmpty {
                if loadError != nil {
                    EmptyStateLine(text: "Google service accounts could not be loaded.")
                } else if isCurrent {
                    EmptyStateLine(text: "ASM has not recorded any service accounts yet.")
                } else {
                    ProgressView("Loading service accounts…")
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            } else {
                GcloudOwnedAccountsTable(
                    rows: rows, selection: $selection, deletingID: deletingID,
                    canReview: canReview, details: showDetails, review: reviewDeletion
                )
            }
            Divider()
            GcloudOwnedAccountsFooter(
                row: selected, isCurrent: isCurrent, loadError: loadError, deleteError: deleteError,
                canReview: selected.map(canReview) ?? false,
                details: { if let selection { showDetails(selection) } },
                review: { if let selected { reviewDeletion(selected) } }
            )
        }
        .task(id: request) { [started = request] in
            await load(started)
        }
        .sheet(item: $presentation) { item in
            switch item {
            case let .details(id):
                if let row = rows.first(where: { $0.id == id }) {
                    GcloudOwnedAccountDetails(row: row)
                } else {
                    GcloudAccountDetailsUnavailable()
                }
            case let .confirm(snapshot):
                GcloudAccountDeletionReview(
                    row: snapshot,
                    isCurrent: canReview(snapshot) && selected == snapshot,
                    deleting: deletingID == snapshot.id
                ) { delete(snapshot) }
                .interactiveDismissDisabled(deletingID != nil)
            }
        }
    }

    private func load(_ started: LoadRequest) async {
        guard !Task.isCancelled, started == request else { return }
        loadError = nil
        do {
            let accounts = try await model.gcloudOwnedAccounts()
            guard !Task.isCancelled, started == request else { return }
            rows = accounts
            loaded = started
            if let selection, !accounts.contains(where: { $0.id == selection }) {
                self.selection = nil
            }
        } catch {
            guard !Task.isCancelled, started == request else { return }
            loaded = nil
            loadError = error.localizedDescription
        }
    }

    private func showDetails(_ id: Int64) {
        guard deletingID == nil else { return }
        selection = id
        presentation = .details(id)
    }

    private func canReview(_ row: GcloudOwnedAccountItem) -> Bool {
        isCurrent && deletingID == nil && row.deletable && row.hasNumericID
    }

    private func reviewDeletion(_ row: GcloudOwnedAccountItem) {
        guard canReview(row), rows.contains(row) else { return }
        selection = row.id
        presentation = .confirm(row)
    }

    private func delete(_ snapshot: GcloudOwnedAccountItem) {
        guard canReview(snapshot), selected == snapshot else { return }
        deletingID = snapshot.id
        deleteError = nil
        Task {
            do {
                // The core rechecks this same identity and lease snapshot before any mutation.
                try await model.deleteGcloudOwnedAccount(snapshot)
            } catch {
                deleteError = error.localizedDescription
            }
            presentation = nil
            deletingID = nil
        }
    }
}

private enum GcloudAccountPresentation: Identifiable {
    case details(Int64)
    case confirm(GcloudOwnedAccountItem)

    var id: String {
        switch self {
        case let .details(id): "details-\(id)"
        case let .confirm(row): "confirm-\(row.id)"
        }
    }
}

private struct GcloudOwnedAccountsHeader: View {
    let refresh: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 16) {
            VStack(alignment: .leading, spacing: 4) {
                Text("ASM-created Google service accounts")
                    .font(.headline)
                    .accessibilityAddTraits(.isHeader)
                Text("Includes accounts from removed generators. This list uses local records, not live Google Cloud status.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            Button(action: refresh) { Label("Refresh List", systemImage: "arrow.clockwise") }
        }
        .padding()
    }
}

private struct GcloudOwnedAccountsTable: View {
    let rows: [GcloudOwnedAccountItem]
    @Binding var selection: Int64?
    let deletingID: Int64?
    let canReview: (GcloudOwnedAccountItem) -> Bool
    let details: (Int64) -> Void
    let review: (GcloudOwnedAccountItem) -> Void

    var body: some View {
        Table(rows, selection: $selection) {
            TableColumn("Service account") { row in
                Text(row.accountName).help(row.accountEmail)
            }
            .width(min: 110, ideal: 170)
            TableColumn("Project") { row in
                Text(row.projectID).help(row.projectID)
            }
            .width(min: 80, ideal: 120)
            TableColumn("Generator") { row in
                if let name = row.generatorName {
                    Text(name).help(name)
                } else {
                    Text("Removed").foregroundStyle(.secondary)
                }
            }
            .width(min: 65, ideal: 100)
            TableColumn("Status") { row in
                if deletingID == row.id {
                    Text("Deleting…")
                } else {
                    let status = row.statusTitle
                    status.help(status)
                }
            }
            .width(min: 100, ideal: 145)
            TableColumn("Leases") { row in
                Text(row.leases.count, format: .number)
            }
            .width(min: 45, ideal: 55)
        }
        .contextMenu(forSelectionType: Int64.self) { ids in
            if let row = rows.first(where: { ids.contains($0.id) }) {
                Button("Details…") { details(row.id) }
                Button(row.reviewTitle, role: .destructive) { review(row) }
                    .disabled(!canReview(row))
            }
        } primaryAction: { ids in
            if let id = ids.first { details(id) }
        }
    }
}

private struct GcloudOwnedAccountsFooter: View {
    let row: GcloudOwnedAccountItem?
    let isCurrent: Bool
    let loadError: String?
    let deleteError: String?
    let canReview: Bool
    let details: () -> Void
    let review: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let loadError {
                Label("Could not refresh the local list: \(loadError)", systemImage: "exclamationmark.triangle")
            }
            if let deleteError {
                Label("Deletion did not finish: \(deleteError)", systemImage: "exclamationmark.triangle")
            }
            HStack {
                if let row {
                    if let reason = row.blockingReason {
                        Text(reason).foregroundStyle(.secondary)
                    } else if !row.deletable || !row.hasNumericID {
                        Text("Deletion is unavailable for this record.").foregroundStyle(.secondary)
                    } else if !isCurrent {
                        Text("Refresh the local list before reviewing deletion.").foregroundStyle(.secondary)
                    }
                } else {
                    Text("Select an account to review its details and leases.").foregroundStyle(.secondary)
                }
                Spacer()
                Button("Details…", action: details).disabled(row == nil)
                Button(row?.reviewTitle ?? "Delete Account…", role: .destructive, action: review)
                    .disabled(!canReview)
            }
        }
        .font(.callout)
        .fixedSize(horizontal: false, vertical: true)
        .padding()
    }
}

private struct GcloudOwnedAccountDetails: View {
    let row: GcloudOwnedAccountItem
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    Text(row.accountName)
                        .font(.title2.weight(.semibold))
                        .accessibilityAddTraits(.isHeader)
                        .textSelection(.enabled)
                    GcloudOwnedAccountFacts(row: row)
                    Divider()
                    GcloudOwnedAccountLeases(leases: row.leases, title: "Dependent ASM leases")
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding()
            }
            Divider()
            HStack {
                if let url = row.consoleURL {
                    Link(destination: url) { Label("Open in Google Cloud Console", systemImage: "arrow.up.right.square") }
                }
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
            .padding()
        }
        .frame(minWidth: 540, idealWidth: 600, minHeight: 380, idealHeight: 510)
    }
}

private struct GcloudAccountDetailsUnavailable: View {
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .trailing, spacing: 16) {
            Text("This account is no longer in the local list.")
            Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
        }
        .padding()
    }
}

private struct GcloudOwnedAccountFacts: View {
    let row: GcloudOwnedAccountItem

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 6) {
                GridRow { Text("Email"); Text(row.accountEmail).textSelection(.enabled) }
                GridRow { Text("Project ID"); Text(row.projectID).textSelection(.enabled) }
                GridRow {
                    Text("Numeric account ID")
                    if let id = row.accountUniqueID, row.hasNumericID {
                        Text(id).monospacedDigit().textSelection(.enabled)
                    } else {
                        Text("Not verified").foregroundStyle(.secondary)
                    }
                }
                GridRow { Text("Status"); row.statusTitle }
                GridRow {
                    Text("Generator")
                    if let name = row.generatorName { Text(name) } else { Text("Removed").foregroundStyle(.secondary) }
                }
                GridRow { Text("Generator ID"); Text(row.generatorID).textSelection(.enabled) }
                if let revision = row.generatorRevision {
                    GridRow { Text("Generator revision"); Text(revision, format: .number) }
                }
                if let status = row.generatorStatus {
                    GridRow { Text("Generator status"); Text(status.title) }
                }
                GridRow { Text("Provisioning sign-in"); Text(row.operatorEmail).textSelection(.enabled) }
                GridRow(alignment: .top) {
                    Text("Recorded project roles")
                    VStack(alignment: .leading) {
                        ForEach(row.permissions, id: \.self) { permission in
                            Text(permission.role).font(.callout.monospaced()).textSelection(.enabled)
                        }
                    }
                }
            }
            switch row.state {
            case .creating:
                Text("ASM did not verify a numeric account ID for this attempt. The account may not exist, and ASM will not delete it by name or email.")
                    .foregroundStyle(.secondary)
            case .created, .projectBound, .tokenCreatorBound:
                Text("Provisioning did not reach Ready. Access may be incomplete.")
                    .foregroundStyle(.secondary)
            case .deletionPending:
                Text("ASM has already stopped local access. Google deletion or role cleanup is not confirmed. If available, retry targets only this same numeric account ID.")
                    .foregroundStyle(.secondary)
            case .deleted:
                Text("This record is retained for audit. The account was deleted and its dependent leases were removed.")
                    .foregroundStyle(.secondary)
            case .ready:
                EmptyView()
            }
            if let reason = row.blockingReason {
                Label(reason, systemImage: "info.circle")
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .font(.callout)
    }
}

private struct GcloudAccountDeletionReview: View {
    let row: GcloudOwnedAccountItem
    let isCurrent: Bool
    let deleting: Bool
    let delete: () -> Void
    @Environment(\.dismiss) private var dismiss

    private var retrying: Bool { row.state == .deletionPending }
    private var heading: LocalizedStringKey {
        retrying ? "Retry deleting this Google service account?" : "Delete this Google service account?"
    }
    private var action: LocalizedStringKey {
        if retrying { return "Retry Deletion" }
        return row.leases.isEmpty ? "Delete Account" : "Delete Account and Leases"
    }

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    Text(heading)
                        .font(.title2.weight(.semibold))
                        .accessibilityAddTraits(.isHeader)
                    Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 6) {
                        GridRow { Text("Service account"); Text(row.accountEmail) }
                        GridRow { Text("Project ID"); Text(row.projectID) }
                        GridRow { Text("Numeric account ID"); Text(row.accountUniqueID ?? "").monospacedDigit() }
                    }
                    .textSelection(.enabled)
                    if retrying {
                        Text("Retry cloud deletion or role cleanup for this exact account. Any leases removed by the earlier attempt will not be restored.")
                    } else {
                        Text("Before contacting Google, ASM will stop delivery and remove the \(row.leases.count) active and ended leases listed below. The generator stays in ASM. Pending approvals for this profile require a fresh review.")
                    }
                    Text("If any of these leases use sentinels, ASM restarts its local proxy, briefly interrupting other proxy connections.")
                    Text("ASM will request deletion in Google Cloud and may clean up this account’s recorded project role bindings. Deletion can affect services outside ASM that use this account. Copies of tokens already issued cannot be individually revoked and may remain usable until expiry.")
                    Divider()
                    GcloudOwnedAccountLeases(leases: row.leases, title: "ASM leases to remove")
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding()
            }
            Divider()
            HStack {
                if deleting {
                    ProgressView("Deletion in progress…").controlSize(.small)
                } else if !isCurrent {
                    Label("The account or lease list changed. Cancel and review it again.", systemImage: "exclamationmark.triangle")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                    .disabled(deleting)
                Button(action, role: .destructive, action: delete)
                    .disabled(!isCurrent || deleting)
            }
            .padding()
        }
        .frame(minWidth: 540, idealWidth: 600, minHeight: 420, idealHeight: 490)
    }
}

private struct GcloudOwnedAccountLeases: View {
    let leases: [GcloudOwnedAccountLeaseItem]
    let title: LocalizedStringKey

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.headline).accessibilityAddTraits(.isHeader)
            if leases.isEmpty {
                Text("No dependent leases are recorded.").foregroundStyle(.secondary)
            } else {
                let active = leases.count(where: { $0.status == .active })
                Text("Active: \(active) · Ended: \(leases.count - active)").foregroundStyle(.secondary)
                LazyVStack(alignment: .leading, spacing: 8) {
                    ForEach(leases, id: \.id) { lease in
                        GcloudOwnedAccountLeaseRow(lease: lease)
                    }
                }
            }
        }
        .font(.callout)
    }
}

private struct GcloudOwnedAccountLeaseRow: View {
    let lease: GcloudOwnedAccountLeaseItem

    private var status: LocalizedStringKey {
        switch lease.status {
        case .active: "Active"
        case .expired: "Ended — expired"
        case .revoked: "Ended — revoked"
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(alignment: .top) {
                if lease.agentLabel.isEmpty {
                    Text(lease.hostLabel)
                } else {
                    Text("\(lease.hostLabel) · \(lease.agentLabel)")
                }
                Spacer()
                Text(status)
            }
            Text("Lease ID: \(lease.id)").font(.caption.monospaced()).textSelection(.enabled)
            if let deadline = lease.deadline {
                Text("Lease deadline: \(deadline, format: .dateTime.year().month().day().hour().minute())")
                    .foregroundStyle(.secondary)
            } else {
                Text("No lease deadline").foregroundStyle(.secondary)
            }
        }
    }
}

private extension GcloudOwnedAccountItem {
    var hasNumericID: Bool {
        guard let id = accountUniqueID, !id.isEmpty else { return false }
        return id.utf8.allSatisfy { (48...57).contains($0) }
    }

    var consoleURL: URL? {
        guard let id = accountUniqueID, hasNumericID else { return nil }
        var components = URLComponents()
        components.scheme = "https"
        components.host = "console.cloud.google.com"
        components.path = "/iam-admin/serviceaccounts/details/\(id)"
        components.queryItems = [URLQueryItem(name: "project", value: projectID)]
        return components.url
    }

    var reviewTitle: LocalizedStringKey {
        state == .deletionPending ? "Retry Deletion…" : "Delete Account…"
    }

    var statusTitle: Text {
        if superseded { return Text("Superseded") }
        if state == .deletionPending { return Text("Deletion unconfirmed") }
        return Text(state.label)
    }
}
