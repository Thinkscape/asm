import Observation
import SwiftUI

/// The exact pending get and delivery decision to which core binds a first-use IAM plan.
struct GcloudSetupTarget: Equatable, Sendable {
    let requestID: String
    let requestExpiry: Date
    let requestedAccess: GcloudAccessRequestItem
    let access: GcloudAccessRequestItem
    let selection: GenerationSelectionItem
    let raw: Bool
    let durationSecs: UInt64?
    let hosts: [String]

    var decision: DecisionItem {
        .approveGet(raw: raw, durationSecs: durationSecs, hosts: hosts, generation: selection)
    }

    @MainActor
    func currentChoice(in model: AppModel) -> GeneratorApprovalChoiceItem? {
        guard let pending = model.shownRequest, pending.id == requestID,
              pending.expiresAt == requestExpiry, requestExpiry > .now,
              case let .get(detail) = pending.detail,
              detail.requestedGeneration == .gcloudAccess(requestedAccess),
              detail.operatorSelectedGcloudProject || access.projectID == requestedAccess.projectID,
              !access.permissions.isEmpty,
              detail.operatorSelectedGrant || access.permissions == requestedAccess.permissions,
              selection.grant == .gcloudAccess(.requested(access: access)),
              detail.vaultID == nil || detail.vaultID == selection.generatorID,
              !(detail.sentinelRequired && raw) else { return nil }
        return detail.generatorChoices.first {
            $0.choice.id == selection.generatorID && $0.choice.revision == selection.generatorRevision
                && $0.choice.available && $0.choice.ceiling == .gcloudAccess(.requested(access: requestedAccess))
        }
    }

    func readyGrant(in choice: GeneratorApprovalChoiceItem) -> GcloudAccessGrantItem? {
        guard access == requestedAccess, let ready = choice.gcloudReady,
              case let .issued(readyAccess, uniqueID, email) = ready, readyAccess == access,
              !uniqueID.isEmpty, !email.isEmpty else { return nil }
        return ready
    }

    @MainActor
    func needsProfile(in model: AppModel) -> Bool {
        guard let choice = currentChoice(in: model) else { return false }
        return readyGrant(in: choice) == nil
    }
}

struct GcloudPlanAuthorization: Equatable {
    let id: String
    let expiresAt: Date
}

@MainActor @Observable
final class GcloudApprovalSetup {
    enum Status: Equatable {
        case preparing
        case prepared(GcloudPlanAuthorization, GcloudProfilePlanItem)
        case failed(String)

        var authorization: GcloudPlanAuthorization? {
            if case let .prepared(authorization, _) = self { return authorization }
            return nil
        }

        var error: String? {
            if case let .failed(message) = self { return message }
            return nil
        }
    }

    private struct Preparation: Equatable {
        let target: GcloudSetupTarget
        let ticket: UUID
        var status: Status
    }

    private var preparation: Preparation?
    private var dismissedPresentation: UInt64?
    private(set) var renewal: UInt64 = 0

    func status(for target: GcloudSetupTarget) -> Status {
        guard let preparation, preparation.target == target else { return .preparing }
        return preparation.status
    }

    func isPresented(_ revision: UInt64) -> Bool {
        dismissedPresentation != revision
    }

    func prepare(for target: GcloudSetupTarget, using model: AppModel) async {
        guard !Task.isCancelled, !model.isResolving(target.requestID), isPresented(model.approvalPresentation),
              target.needsProfile(in: model) else { return }
        cancelPreparation(using: model)
        let ticket = UUID()
        preparation = Preparation(target: target, ticket: ticket, status: .preparing)
        defer {
            if Task.isCancelled, preparation?.ticket == ticket { cancelPreparation(using: model) }
        }
        do {
            let (plan, expiresAt) = try await model.gcloudProfilePlan(
                requestID: target.requestID, decision: target.decision
            )
            guard !Task.isCancelled, preparation?.ticket == ticket, target.needsProfile(in: model) else {
                discard(plan.planID, using: model)
                return
            }
            // An existing profile for an edited permission set still needs an exact reviewed plan.
            guard let id = plan.planID, !id.isEmpty, let expiresAt, expiresAt > .now,
                  expiresAt <= target.requestExpiry, plan.projectID == target.access.projectID,
                  !plan.serviceAccountName.isEmpty, !plan.serviceAccountEmail.isEmpty,
                  (!plan.ready || !(plan.serviceAccountUniqueID ?? "").isEmpty),
                  plan.adminPrincipal.hasPrefix("user:"), plan.adminPrincipal.count > "user:".count,
                  plan.serviceAccountRole == "roles/iam.serviceAccountTokenCreator",
                  Set(plan.projectRoles) == Set(target.access.permissions.map(\.role)),
                  Set(plan.scopes) == Set(target.access.permissions.map(\.scope)) else {
                discard(plan.planID, using: model)
                preparation?.status = .failed(String(localized: "The IAM plan was invalid or expired. Reopen this request to try again."))
                return
            }
            let authorization = GcloudPlanAuthorization(id: id, expiresAt: expiresAt)
            preparation?.status = .prepared(authorization, plan)
            try? await Task.sleep(for: .seconds(max(0, expiresAt.timeIntervalSinceNow)))
            guard !Task.isCancelled, preparation?.ticket == ticket else { return }
            discard(id, using: model)
            preparation = nil
            renewal &+= 1
        } catch {
            guard preparation?.ticket == ticket, !Task.isCancelled, target.needsProfile(in: model) else { return }
            preparation?.status = .failed(error.localizedDescription)
        }
    }

    func approve(
        _ target: GcloudSetupTarget, authorization: GcloudPlanAuthorization?,
        ready: GcloudAccessGrantItem?, using model: AppModel
    ) {
        guard !model.isResolving(target.requestID), isPresented(model.approvalPresentation),
              let live = target.currentChoice(in: model), target.readyGrant(in: live) == ready else { return }
        if let authorization {
            guard ready == nil, authorization.expiresAt > .now,
                  status(for: target).authorization == authorization else { return }
            // The combined core operation consumes the plan. Do not discard it on dismissal.
            preparation = nil
        } else {
            guard ready != nil else { return }
            cancelPreparation(using: model)
        }
        model.resolve(target.requestID, target.decision, gcloudPlanID: authorization?.id)
    }

    func deny(_ requestID: String, reason: String, using model: AppModel) {
        guard !model.isResolving(requestID), isPresented(model.approvalPresentation),
              model.shownRequestID == requestID else { return }
        cancelPreparation(forRequest: requestID, using: model)
        model.resolve(requestID, .deny(reason: reason))
    }

    func cancelPreparation(forRequest requestID: String?, using model: AppModel) {
        guard let requestID else { return }
        if preparation?.target.requestID == requestID { cancelPreparation(using: model) }
    }

    func retry(for target: GcloudSetupTarget, using model: AppModel) {
        guard !model.isResolving(target.requestID), isPresented(model.approvalPresentation),
              target.needsProfile(in: model), case .failed = status(for: target) else { return }
        cancelPreparation(forRequest: target.requestID, using: model)
        renewal &+= 1
    }

    private func cancelPreparation(using model: AppModel) {
        let id = preparation?.status.authorization?.id
        preparation = nil
        discard(id, using: model)
    }

    func dismiss(using model: AppModel) {
        dismissedPresentation = model.approvalPresentation
        cancelPreparation(using: model)
    }

    private func discard(_ id: String?, using model: AppModel) {
        guard let id else { return }
        Task { try? await model.gcloudCancelProfile(planID: id) }
    }
}

struct GcloudInlineIAMPlan: View {
    let plan: GcloudProfilePlanItem

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(plan.ready
                 ? "Generating this token uses the existing profile without changing IAM."
                 : "Generating this token authorizes IAM changes that persist after the lease ends. If setup fails, partial changes may remain.")
                .font(.callout)

            ApprovalDisclosure(plan.ready ? "Existing IAM profile" : "IAM changes on approval") {
                VStack(alignment: .leading, spacing: 6) {
                    Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 10, verticalSpacing: 5) {
                        row(plan.serviceAccountUniqueID == nil ? "Create account" : "Service account") {
                            Text(verbatim: plan.serviceAccountEmail)
                            if let id = plan.serviceAccountUniqueID {
                                Text("Immutable ID: \(id)")
                            }
                        }
                        row("Project roles") {
                            ForEach(plan.projectRoles, id: \.self) { role in Text(verbatim: role) }
                            if plan.ready {
                                Text("In \(plan.projectID)")
                            } else {
                                Text("To this account in \(plan.projectID)")
                            }
                        }
                        row("OAuth scopes") {
                            ForEach(plan.scopes, id: \.self) { scope in
                                Text(verbatim: scope).monospaced()
                            }
                        }
                        row("Token Creator") {
                            Text(verbatim: plan.serviceAccountRole)
                            if plan.ready {
                                Text("\(plan.adminPrincipal) on this account")
                            } else {
                                Text("To \(plan.adminPrincipal) on this account only")
                            }
                        }
                    }
                    if !plan.ready {
                        Text("Google Cloud usage can incur charges.")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(plan.messages, id: \.self) { message in
                        Text(verbatim: message)
                    }
                }
                .font(.caption)
            }
        }
        .fixedSize(horizontal: false, vertical: true)
    }

    private func row<Content: View>(
        _ label: LocalizedStringKey, @ViewBuilder content: () -> Content
    ) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 2, content: content)
                .foregroundStyle(.primary)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

struct GcloudAccessClaimsSummary: View {
    let heading: LocalizedStringKey
    let access: GcloudAccessRequestItem

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            LabeledContent("IAM project") { GcloudIAMIdentifier(value: access.projectID) }
            Text(heading).font(.subheadline.weight(.semibold)).accessibilityAddTraits(.isHeader)
            GcloudAccessTechnicalDetails(access: access)
        }
    }
}

/// Exact permission mapping for disclosure content and lease details.
struct GcloudAccessTechnicalDetails: View {
    let access: GcloudAccessRequestItem

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(access.permissions, id: \.self) { permission in
                let details = CoreBridge.gcloudPermissionDetails(permission)
                VStack(alignment: .leading, spacing: 2) {
                    Text(verbatim: details.claim).font(.callout.monospaced().weight(.semibold))
                    GcloudIAMIdentifier(value: details.role)
                        .accessibilityLabel(Text("IAM role: \(details.role)"))
                    GcloudIAMIdentifier(value: details.scope)
                        .accessibilityLabel(Text("OAuth scope: \(details.scope)"))
                }
                .accessibilityElement(children: .combine)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

private struct GcloudIAMIdentifier: View {
    let value: String

    var body: some View {
        Text(verbatim: value)
            .font(.caption.monospaced())
            .textSelection(.enabled)
            .fixedSize(horizontal: false, vertical: true)
    }
}

enum GcloudManagedIAMWarning {
    static var text: LocalizedStringKey {
        "The profile grants project-wide IAM roles. OAuth scopes limit API calls but do not enforce a resource or project boundary. Inherited access and IAM changes outside ASM can change what the token can do."
    }
}
