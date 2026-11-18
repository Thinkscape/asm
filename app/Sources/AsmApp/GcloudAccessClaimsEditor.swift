import SwiftUI

enum GcloudApprovalProjectList {
    case loading
    case loaded(alternatives: [String], expiresAt: Date)
    case failed(String)
    case expired
}

struct GcloudAccessClaimsEditor: View {
    let request: GcloudAccessRequestItem
    let allowed: [GcloudPermissionItem]
    @Binding var selection: Set<GcloudPermissionItem>
    var projects: GcloudApprovalProjectList?
    var selectedProjectID: String?
    let selectProject: (String?) -> Void
    let reloadProjects: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let projects {
                GcloudProjectChecklist(
                    requested: request.projectID, selected: selectedProjectID, projects: projects,
                    select: selectProject, reload: reloadProjects
                )
            } else {
                LabeledContent {
                    Text(verbatim: request.projectID).textSelection(.enabled)
                } label: {
                    SectionLabel("Requested project")
                }
            }
            if allowed.isEmpty {
                SectionLabel("Requested permissions").accessibilityAddTraits(.isHeader)
                ForEach(request.permissions, id: \.self) { permission in
                    GcloudAccessPermissionLabel(permission: permission)
                }
            } else {
                SectionLabel("Permissions (\(selection.count) selected)").accessibilityAddTraits(.isHeader)
                GcloudPermissionGrid(requested: request.permissions, allowed: allowed, selection: $selection)
            }
            Text("OAuth scopes don’t isolate access to this project; IAM grants determine access.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
    }
}

private struct GcloudPermissionGrid: View {
    let requested: [GcloudPermissionItem]
    let allowed: [GcloudPermissionItem]
    @Binding var selection: Set<GcloudPermissionItem>

    var body: some View {
        let services = GcloudPermissionService.all.filter { service in
            service.permissions.contains { allowed.contains($0) || requested.contains($0) }
        }
        Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 8) {
            ForEach(services) { service in
                let available = service.permissions.filter(allowed.contains)
                let unavailable = service.permissions.filter { requested.contains($0) && !allowed.contains($0) }
                let descriptions = available.isEmpty ? unavailable : available
                GridRow {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(verbatim: service.id)
                        ForEach(unavailable, id: \.self) { permission in
                            Text("\(permission.claim) (requested) (unavailable)",
                                 comment: "A Google Cloud permission claim requested by the paired client but unavailable for approval.")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityElement(children: .combine)
                    .help(descriptions.map { String(localized: $0.approvalTitle) }.joined(separator: "\n"))
                    if available.isEmpty {
                        Text("None").disabled(true)
                    } else {
                        let levels = GcloudPermissionLevels(permissions: service.permissions, available: available)
                        PermissionLevelPicker(
                            label: service.id, options: levels.options.map(\.label),
                            requested: levels.label(for: available.filter(requested.contains)),
                            level: $selection[levelFor: levels]
                        )
                    }
                }
            }
        }
    }
}

private struct GcloudPermissionService: Identifiable {
    let id: String
    var permissions: [GcloudPermissionItem]

    static let all: [Self] = {
        var services: [Self] = []
        for permission in GcloudPermissionItem.allCases {
            let service = String(permission.claim.prefix { $0 != "=" })
            if let index = services.firstIndex(where: { $0.id == service }) {
                services[index].permissions.append(permission)
            } else {
                services.append(Self(id: service, permissions: [permission]))
            }
        }
        return services
    }()
}

private struct GcloudPermissionLevels: Hashable {
    struct Option: Hashable {
        let label: String
        let permissions: [GcloudPermissionItem]

        init(_ permissions: [GcloudPermissionItem]) {
            self.permissions = permissions
            label = permissions.map { $0.claim.drop(while: { $0 != "=" }).dropFirst() }.joined(separator: " + ")
        }
    }

    let permissions: [GcloudPermissionItem]
    let options: [Option]

    init(permissions: [GcloudPermissionItem], available: [GcloudPermissionItem]) {
        self.permissions = permissions
        var options = available.map { Option([$0]) }
        // Storage's read and create claims are independent; offer both only if both are allowed.
        if available.count > 1 { options.append(Option(available)) }
        self.options = options
    }

    func label(for permissions: [GcloudPermissionItem]) -> String? {
        options.first { $0.permissions == permissions }?.label
    }
}

private struct GcloudProjectChecklist: View {
    let requested: String
    let selected: String?
    let projects: GcloudApprovalProjectList
    let select: (String?) -> Void
    let reload: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            SectionLabel("Project (choose one)").accessibilityAddTraits(.isHeader)
            GcloudProjectCheckbox(projectID: requested, requested: true, selected: selected == requested, select: select)
            switch projects {
            case .loading:
                ProgressView("Loading Google Cloud projects…").controlSize(.small)
            case let .loaded(alternatives, _):
                if alternatives.isEmpty {
                    Text("No other active projects are visible to this connection.")
                        .font(.caption).foregroundStyle(.secondary)
                } else {
                    LazyVStack(alignment: .leading, spacing: 6) {
                        ForEach(alternatives, id: \.self) { projectID in
                            GcloudProjectCheckbox(projectID: projectID, requested: false, selected: selected == projectID, select: select)
                        }
                    }
                }
                Button("Refresh projects", action: reload)
            case let .failed(message):
                Text("Couldn’t load Google Cloud projects: \(message)")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                Button("Retry project lookup", action: reload)
            case .expired:
                Text("The project list expired. Refresh it to select a different project.")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                Button("Refresh projects", action: reload)
            }
        }
    }
}

private struct GcloudProjectCheckbox: View {
    let projectID: String
    let requested: Bool
    let selected: Bool
    let select: (String?) -> Void

    var body: some View {
        Toggle(isOn: Binding(get: { selected }, set: { select($0 ? projectID : nil) })) {
            if requested {
                Text("\(projectID) (requested)", comment: "The ID of the project originally requested by the paired client.")
            } else {
                Text(verbatim: projectID)
            }
        }
        .toggleStyle(.checkbox)
        .fixedSize(horizontal: false, vertical: true)
    }
}

private struct GcloudAccessPermissionLabel: View {
    let permission: GcloudPermissionItem

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(permission.approvalTitle)
            Text(verbatim: permission.claim).font(.caption).foregroundStyle(.secondary)
        }
        .fixedSize(horizontal: false, vertical: true)
        .accessibilityElement(children: .combine)
    }
}

private extension Set where Element == GcloudPermissionItem {
    subscript(levelFor levels: GcloudPermissionLevels) -> String? {
        get { levels.label(for: levels.permissions.filter(contains)) }
        set {
            let selected: [Element]
            if let newValue {
                guard let option = levels.options.first(where: { $0.label == newValue }) else { return }
                selected = option.permissions
            } else {
                selected = []
            }
            subtract(levels.permissions)
            formUnion(selected)
        }
    }
}
