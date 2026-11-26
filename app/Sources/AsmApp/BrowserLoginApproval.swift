import SwiftUI

/// Metadata only; the stable identity and the displayed metadata go back to the core for revalidation.
struct LoginChoiceCatalog: Sendable {
    struct Candidate: Identifiable, Sendable {
        enum SiteMatch: Int, Sendable {
            case none, related, exact
        }

        let choice: LoginChoiceItem
        let accountExact: Bool
        let siteMatch: SiteMatch
        var id: LoginChoiceItem.ID { choice.id }
        var score: Int { (accountExact ? 3 : 0) + siteMatch.rawValue }

        func includes(_ search: String) -> Bool {
            choice.title.localizedCaseInsensitiveContains(search)
                || choice.vaultName.localizedCaseInsensitiveContains(search)
                || choice.username?.localizedCaseInsensitiveContains(search) == true
                || choice.savedHosts.contains { $0.localizedCaseInsensitiveContains(search) }
        }
    }

    let candidates: [Candidate]
    let unavailableVaults: [String]

    init(_ snapshot: LoginChoicesItem, detail: LoginDetail) {
        let siteHost = loginURLHost(detail.site ?? detail.url)
        let siteDomain = siteHost.flatMap(CoreBridge.registrableDomain)
        let parentSuffix = siteHost.map { "." + $0 }
        var isRelated: [String: Bool] = [:]
        candidates = snapshot.items.map { choice in
            let accountExact = detail.account.map { exactUsername($0, choice.username) } ?? false
            var siteMatch = Candidate.SiteMatch.none
            if let siteHost, let parentSuffix {
                if choice.savedHosts.contains(siteHost) {
                    siteMatch = .exact
                } else if let siteDomain {
                    for host in choice.savedHosts {
                        let related = isRelated[host] ?? {
                            let match = (siteHost.hasSuffix("." + host) || host.hasSuffix(parentSuffix))
                                && CoreBridge.registrableDomain(host) == siteDomain
                            isRelated[host] = match
                            return match
                        }()
                        if related {
                            siteMatch = .related
                            break
                        }
                    }
                }
            }
            return Candidate(choice: choice, accountExact: accountExact, siteMatch: siteMatch)
        }.sorted { left, right in
            if left.score != right.score { return left.score > right.score }
            let titleOrder = left.choice.title.localizedStandardCompare(right.choice.title)
            if titleOrder != .orderedSame { return titleOrder == .orderedAscending }
            let vaultOrder = left.choice.vaultName.localizedStandardCompare(right.choice.vaultName)
            if vaultOrder != .orderedSame { return vaultOrder == .orderedAscending }
            if left.id.vaultID != right.id.vaultID { return left.id.vaultID < right.id.vaultID }
            return left.id.key < right.id.key
        }
        unavailableVaults = snapshot.unavailableVaults
    }
}

private func loginURLHost(_ url: String) -> String? {
    URL(string: url)?.host()?.lowercased()
}

private func exactUsername(_ requested: String, _ saved: String?) -> Bool {
    saved?.utf8.elementsEqual(requested.utf8) == true
}

/// Request hints and vault labels are data. Make invisible formatting and line breaks visible in review.
private func loginReviewText(_ raw: String) -> String {
    let scalars = raw.unicodeScalars
    func needsEscape(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.properties.generalCategory {
        case .control, .format, .lineSeparator, .paragraphSeparator: true
        default: scalar == "\\"
        }
    }
    guard let first = scalars.firstIndex(where: needsEscape) else { return raw }
    var display = ""
    display.unicodeScalars.append(contentsOf: scalars[..<first])
    for scalar in scalars[first...] {
        if needsEscape(scalar) {
            display += "\\u{\(String(scalar.value, radix: 16))}"
        } else {
            display.unicodeScalars.append(scalar)
        }
    }
    return display
}

struct BrowserLoginApproval: View {
    let context: RequestContext
    let detail: LoginDetail
    let durations: [LeaseDuration]
    let model: AppModel

    var body: some View {
        let revision = model.loginChoicesRevision
        let presentation = model.approvalPresentation
        BrowserLoginReview(
            context: context, detail: detail, durations: durations, vaults: model.vaults,
            revision: revision, presentation: presentation,
            isCurrent: {
                model.loginChoicesRevision == revision && model.approvalPresentation == presentation
                    && model.shownRequestID == context.request.id && model.shownRequest?.detail == .login(detail)
                    && !model.isResolving(context.request.id)
            },
            loadChoices: { try await model.loginChoices(for: detail) },
            openVaultSettings: { model.showVaultSettings(unlock: $0) }
        )
        .id(detail)
    }
}

struct BrowserLoginReview: View {
    let context: RequestContext
    let detail: LoginDetail
    let durations: [LeaseDuration]
    let vaults: [VaultItem]
    let revision: UInt64
    let presentation: UInt64
    let isCurrent: () -> Bool
    let loadChoices: () async throws -> LoginChoiceCatalog
    let openVaultSettings: (String?) -> Void

    @State private var catalog: LoginChoiceCatalog?
    @State private var results: [LoginChoiceCatalog.Candidate] = []
    @State private var selection: LoginChoiceItem?
    @State private var search = ""
    @FocusState private var searchFocused: Bool
    @State private var finishedLoad: LoadKey?
    @State private var reload = 0
    @State private var loadError: String?
    @State private var selectionInvalidated = false
    @State private var aliasConfirmed = false
    @State private var domainConfirmed = false
    @State private var enabledExtras = Set<String>()
    @State private var duration: UInt64
    @State private var editingReason = false

    init(
        context: RequestContext, detail: LoginDetail, durations: [LeaseDuration], vaults: [VaultItem],
        revision: UInt64, presentation: UInt64, isCurrent: @escaping () -> Bool,
        loadChoices: @escaping () async throws -> LoginChoiceCatalog,
        openVaultSettings: @escaping (String?) -> Void
    ) {
        self.context = context
        self.detail = detail
        self.durations = durations
        self.vaults = vaults
        self.revision = revision
        self.presentation = presentation
        self.isCurrent = isCurrent
        self.loadChoices = loadChoices
        self.openVaultSettings = openVaultSettings
        _duration = State(initialValue: detail.broker ? 3600 : 900)
    }

    private struct LoadKey: Equatable {
        let revision: UInt64
        let presentation: UInt64
        let reload: Int
        let detail: LoginDetail
    }

    private var loadKey: LoadKey {
        LoadKey(revision: revision, presentation: presentation, reload: reload, detail: detail)
    }

    private var approvedOrigins: [String] {
        guard detail.broker, let primary = detail.fillOrigins.first else { return [] }
        return [primary] + detail.fillOrigins.dropFirst().filter(enabledExtras.contains)
    }

    private func review(_ choice: LoginChoiceItem) -> LoginReview {
        // The hint only ranks candidates; it never authorizes a destination. Even a related
        // host is a scope change if it does not exactly match a saved hostname.
        let destinations = detail.broker ? approvedOrigins : [detail.url]
        let unmatched = destinations.filter { url in
            guard let host = loginURLHost(url) else { return true }
            return !choice.savedHosts.contains(host)
        }
        let hintMismatch = detail.site.flatMap(loginURLHost).map { !choice.savedHosts.contains($0) } ?? false
        let requestedAlias = detail.account.flatMap { exactUsername($0, choice.username) ? nil : $0 }
        return LoginReview(unmatchedDestinations: unmatched, hintMismatch: hintMismatch, requestedAlias: requestedAlias)
    }

    private var maximumDuration: UInt64 { detail.broker ? .max : 3600 }

    private func canApprove(_ review: LoginReview?) -> Bool {
        guard let review, finishedLoad == loadKey, catalog != nil,
              isCurrent(), context.armed, !editingReason, duration > 0, duration <= maximumDuration,
              !detail.broker || !approvedOrigins.isEmpty else { return false }
        return (!review.requiresDomainConfirmation || domainConfirmed)
            && (review.requestedAlias == nil || aliasConfirmed)
    }

    var body: some View {
        let key = loadKey
        let current = finishedLoad == key
        let review = selection.map(self.review)
        let approvalTitle: LocalizedStringKey = detail.broker ? "Open sign-in browser" : "Allow single-use login"
        ApprovalScaffold(error: context.error, footnote: nil) {
            ApprovalHeader(title: context.requesterTitle,
                           subtitle: detail.broker ? Text("asks you to sign in") : Text("asks for a single-use browser login"),
                           queue: context.queue) { AppIconImage() }
        } content: {
            ReasonBlock(reason: detail.reason)
            LoginRequestScope(detail: detail, enabledExtras: enabledExtras, setOrigin: setOrigin)
            LoginChoiceSection(search: $search, searchFocused: $searchFocused, ready: current,
                               catalog: current ? catalog : nil, results: results, choice: current ? selection : nil,
                               error: current ? loadError : nil, selectionInvalidated: selectionInvalidated,
                               choose: choose, change: change, refresh: { reload &+= 1 })
            if current, let catalog, !catalog.unavailableVaults.isEmpty {
                LoginUnavailableVaults(names: catalog.unavailableVaults, vaults: vaults, openSettings: openVaultSettings)
            }
            if current, let review {
                LoginConfirmation(review: review, aliasConfirmed: $aliasConfirmed, domainConfirmed: $domainConfirmed)
            }
            GetDurationPicker(durations: durations, duration: $duration, maxSeconds: maximumDuration)
        } details: {
            RequestMetaRows(context: context)
        } actions: {
            ApprovalActions(cannedReasons: ["wrong account or destination", "provide a better reason"],
                            armed: context.armed, escapeDenies: !searchFocused,
                            editingReason: $editingReason, deny: context.deny) {
                // No default keyboard action: Return in the search field must not approve a login.
                Button(approvalTitle, action: approve)
                    .buttonStyle(.panel)
                    .disabled(!canApprove(review))
            }
        }
        .task(id: key) { await load(key) }
        .onChange(of: search) {
            if selection != nil { choose(nil) }
            filterResults()
        }
    }

    private func load(_ key: LoadKey) async {
        guard !Task.isCancelled, key == loadKey else { return }
        do {
            let next = try await loadChoices()
            guard !Task.isCancelled, key == loadKey else { return }
            if let selection, !next.candidates.contains(where: { $0.choice == selection }) {
                choose(nil)
                selectionInvalidated = true
            }
            catalog = next
            loadError = nil
        } catch {
            guard !Task.isCancelled, key == loadKey else { return }
            choose(nil)
            catalog = nil
            loadError = error.localizedDescription
        }
        filterResults()
        finishedLoad = key
    }

    private func filterResults() {
        let query = search.trimmingCharacters(in: .whitespacesAndNewlines)
        let candidates = catalog?.candidates ?? []
        results = query.isEmpty ? candidates : candidates.filter { $0.includes(query) }
    }

    private func choose(_ choice: LoginChoiceItem?) {
        selection = choice
        aliasConfirmed = false
        domainConfirmed = false
        selectionInvalidated = false
        if choice != nil { searchFocused = false }
    }

    private func change() {
        choose(nil)
        searchFocused = true
    }

    private func setOrigin(_ origin: String, _ enabled: Bool) {
        if enabled { enabledExtras.insert(origin) } else { enabledExtras.remove(origin) }
        domainConfirmed = false
    }

    private func approve() {
        guard let selection, canApprove(review(selection)) else { return }
        context.resolve(.approveLogin(selection: selection, durationSecs: duration, fillOrigins: approvedOrigins))
    }
}

struct LoginScopeValue: View {
    let label: LocalizedStringKey
    let value: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            SectionLabel(label)
            if let value {
                Text(verbatim: loginReviewText(value))
                    .font(.callout.monospaced())
                    .textSelection(.enabled)
            } else {
                Text("Not supplied").font(.callout).foregroundStyle(.secondary)
            }
        }
        .fixedSize(horizontal: false, vertical: true)
        .accessibilityElement(children: .combine)
    }
}

private struct LoginRequestScope: View {
    let detail: LoginDetail
    let enabledExtras: Set<String>
    let setOrigin: (String, Bool) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let account = detail.account {
                LoginScopeValue(label: "Requested account (unverified)", value: account)
            }
            if let site = detail.site {
                LoginScopeValue(label: "Requested site (unverified)", value: site)
                Text("This site helps find a login. It does not authorize a destination.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            if detail.broker {
                LoginScopeValue(label: "Chrome opens this exact URL", value: detail.url)
                LoginScopeValue(label: "Always enabled for fill and export", value: detail.fillOrigins.first)
                if !detail.fillOrigins.dropFirst().isEmpty {
                    SectionLabel("Additional origins requested for fill and export")
                    ForEach(detail.fillOrigins.dropFirst(), id: \.self) { origin in
                        Toggle(isOn: Binding(get: { enabledExtras.contains(origin) }, set: { setOrigin(origin, $0) })) {
                            Text(verbatim: loginReviewText(origin)).font(.callout.monospaced())
                        }
                    }
                }
                Text("Fills in Chrome on this Mac without submitting. Handing over exports local storage for the primary origin and cookies valid on the enabled hosts, including applicable parent-domain cookies.")
                    .font(.caption).foregroundStyle(.secondary)
            } else {
                LoginScopeValue(label: "Password destination — exact URL", value: detail.url)
                Text("The agent receives the saved username, a single-use password substitute for this URL, and, if available, a one-time code. It can refresh the code until this grant ends.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .fixedSize(horizontal: false, vertical: true)
    }
}

private struct LoginUnavailableVaults: View {
    let names: [String]
    let vaults: [VaultItem]
    let openSettings: (String?) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label("Some vaults are unavailable", systemImage: "exclamationmark.triangle")
                .font(.callout.weight(.semibold))
            Text("Search does not include items from these vaults. Unlock them or check Vault Settings, then refresh.")
                .font(.caption).foregroundStyle(.secondary)
            ForEach(names, id: \.self) { name in
                HStack {
                    Text(verbatim: loginReviewText(name))
                        .font(.callout).fixedSize(horizontal: false, vertical: true)
                    if let vault = vaults.first(where: { $0.name == name && $0.canUnlock }) {
                        Spacer(minLength: 8)
                        Button("Unlock…") { openSettings(vault.id) }
                            .accessibilityLabel("Unlock \(Text(verbatim: loginReviewText(name)))")
                    }
                }
            }
            Button("Open Vault Settings") { openSettings(nil) }
        }
        .padding(9)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 8))
    }
}

private struct LoginChoiceSection: View {
    @Binding var search: String
    let searchFocused: FocusState<Bool>.Binding
    let ready: Bool
    let catalog: LoginChoiceCatalog?
    let results: [LoginChoiceCatalog.Candidate]
    let choice: LoginChoiceItem?
    let error: String?
    let selectionInvalidated: Bool
    let choose: (LoginChoiceItem?) -> Void
    let change: () -> Void
    let refresh: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            ViewThatFits(in: .horizontal) {
                HStack {
                    title
                    Spacer()
                    refreshButton
                }
                VStack(alignment: .leading, spacing: 6) {
                    title
                    refreshButton
                }
            }
            TextField("Search all exposed logins", text: $search)
                .textFieldStyle(.roundedBorder)
                .accessibilityLabel("Search all exposed logins")
                .focused(searchFocused)
            if !ready {
                ProgressView("Loading exposed logins…").controlSize(.small)
            } else if let error {
                ErrorLine(message: error)
            } else if let catalog {
                if selectionInvalidated {
                    Text("The selected login changed or became unavailable. Choose it again after checking its details.")
                        .font(.callout)
                }
                if let choice {
                    VStack(alignment: .leading, spacing: 6) {
                        HStack {
                            SectionLabel("Selected login")
                            Spacer()
                            Button("Change", action: change).accessibilityLabel("Change selected login")
                        }
                        LoginChoiceMetadata(choice: choice)
                    }
                    .padding(9)
                    .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))
                } else if catalog.candidates.isEmpty {
                    Text(catalog.unavailableVaults.isEmpty
                         ? "There are no exposed password logins."
                         : "No password logins could be found in available vaults.")
                    .font(.callout).foregroundStyle(.secondary)
                } else if results.isEmpty {
                    Text("No exposed logins match your search.").font(.callout).foregroundStyle(.secondary)
                } else {
                    if catalog.candidates.first?.score == 0 {
                        Text("No suggested matches. You can choose from all exposed logins below.")
                            .font(.callout).foregroundStyle(.secondary)
                    }
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 3) {
                            ForEach(results) { candidate in
                                LoginCandidateRow(candidate: candidate) { choose(candidate.choice) }
                            }
                        }
                    }
                    .defaultScrollAnchor(.top)
                    .frame(maxHeight: 172)
                    .scrollBounceBehavior(.basedOnSize)
                }
            }
        }
    }

    private var title: some View {
        Text("Vault login").font(.headline).accessibilityAddTraits(.isHeader)
    }

    private var refreshButton: some View {
        Button("Refresh logins", action: refresh).disabled(!ready)
    }
}

private struct LoginCandidateRow: View {
    let candidate: LoginChoiceCatalog.Candidate
    let select: () -> Void

    var body: some View {
        Button(action: select) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 3) {
                    Text(verbatim: loginReviewText(candidate.choice.username ?? candidate.choice.title))
                        .font(.headline)
                    Text("\(Text(verbatim: loginReviewText(candidate.choice.title))) · \(Text(verbatim: loginReviewText(candidate.choice.vaultName)))")
                        .font(.caption).foregroundStyle(.secondary)
                    if !candidate.choice.savedHosts.isEmpty {
                        Text(verbatim: candidate.choice.savedHosts.map(loginReviewText).formatted())
                            .font(.caption.monospaced()).foregroundStyle(.secondary)
                    }
                }
                Spacer(minLength: 8)
                Image(systemName: "chevron.right").font(.caption).foregroundStyle(.secondary).accessibilityHidden(true)
            }
            .padding(8)
            .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 8))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

private struct LoginChoiceMetadata: View {
    let choice: LoginChoiceItem

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            if let username = choice.username, !username.isEmpty {
                Text(verbatim: loginReviewText(username)).font(.headline)
                Text("Item: \(Text(verbatim: loginReviewText(choice.title)))")
            } else {
                Text(verbatim: loginReviewText(choice.title)).font(.headline)
                Text("No saved username")
            }
            Text("Vault: \(Text(verbatim: loginReviewText(choice.vaultName)))")
            if choice.savedHosts.isEmpty {
                Text("No saved hosts")
            } else {
                Text("Saved hosts: \(Text(verbatim: choice.savedHosts.map(loginReviewText).formatted()))")
            }
            if choice.hasTotp { Text("Has one-time codes") }
        }
        .font(.callout)
        .fixedSize(horizontal: false, vertical: true)
        .accessibilityElement(children: .combine)
    }
}

private struct LoginReview {
    let unmatchedDestinations: [String]
    let hintMismatch: Bool
    let requestedAlias: String?
    var requiresDomainConfirmation: Bool { hintMismatch || !unmatchedDestinations.isEmpty }
}

private struct LoginConfirmation: View {
    let review: LoginReview
    @Binding var aliasConfirmed: Bool
    @Binding var domainConfirmed: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let account = review.requestedAlias {
                Text("The saved username differs from the requested account \(Text(verbatim: loginReviewText(account))).")
                    .font(.callout)
                Toggle("I verified that the selected login is an alias for the requested account.", isOn: $aliasConfirmed)
            }
            if review.requiresDomainConfirmation {
                if review.hintMismatch {
                    Text("The requested site does not exactly match a saved host on this login.").font(.callout)
                }
                if !review.unmatchedDestinations.isEmpty {
                    Text("These destinations do not exactly match a saved host on this login:").font(.callout)
                    ForEach(review.unmatchedDestinations, id: \.self) { destination in
                        Text(verbatim: loginReviewText(destination)).font(.callout.monospaced()).textSelection(.enabled)
                    }
                }
                Toggle("I verified the site and destinations are correct for this login.", isOn: $domainConfirmed)
            }
        }
        .fixedSize(horizontal: false, vertical: true)
    }
}
