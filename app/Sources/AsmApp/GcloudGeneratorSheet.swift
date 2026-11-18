import Foundation
import Observation
import SwiftUI
import UniformTypeIdentifiers

struct GcloudGeneratorSheet: View {
    static let accountPermissionsURL = URL(string: "https://myaccount.google.com/permissions")!

    @Environment(\.dismiss) private var dismiss
    @State private var state: GcloudConnectionSetup
    @State private var choosingSDK = false

    init(model: AppModel, editing: (generator: GeneratorItem, config: GcloudConnectionConfigItem)? = nil) {
        _state = State(initialValue: GcloudConnectionSetup(model: model, editing: editing))
    }

    var body: some View {
        @Bindable var state = state
        VStack(spacing: 0) {
            Form {
                Section("Google Cloud connection") {
                    TextField("Name", text: $state.name)
                }
                GcloudSDKSection(state: state, locateSDK: { choosingSDK = true })
                GcloudSignInSection(state: state)
                GcloudConnectionUsageSection()
                if let error = state.saveError {
                    Section("Could not save") { Text(error).textSelection(.enabled) }
                }
            }
            .formStyle(.grouped)
            .disabled(state.saving)
            SheetButtons(saveTitle: "Save", problem: state.problem, saving: state.saving, cancel: {
                guard !state.saving else { return }
                state.close()
                dismiss()
            }, save: {
                state.save { dismiss() }
            })
        }
        .frame(minWidth: 580, idealWidth: 640, maxWidth: 760, minHeight: 470, idealHeight: 620)
        .task { state.checkSDK() }
        .onDisappear(perform: state.close)
        .interactiveDismissDisabled(state.saving)
        .fileImporter(isPresented: $choosingSDK, allowedContentTypes: [.item]) { state.chooseSDK($0) }
        .alert("Generator saved", isPresented: $state.showingSaveWarning) {
            Button("OK") { dismiss() }
        } message: {
            Text(state.savedWarning ?? "")
        }
    }
}

@MainActor
@Observable
private final class GcloudConnectionSetup {
    private let model: AppModel
    private let editing: (generator: GeneratorItem, config: GcloudConnectionConfigItem)?

    var name: String
    var showingSaveWarning = false
    private(set) var saving = false
    private(set) var saveError: String?
    private(set) var savedWarning: String?
    private(set) var sdk: GcloudSdkItem?
    private(set) var checkingSDK = false
    private(set) var sdkError: String?
    private(set) var signingIn = false
    private(set) var loginError: String?
    private var login: (id: String, config: GcloudConnectionConfigItem)?
    @ObservationIgnored private var candidateSDKPath: String?
    @ObservationIgnored private var loginOperation: UUID?
    @ObservationIgnored private var pendingLoginID: String?
    @ObservationIgnored private var closed = false

    init(model: AppModel, editing: (generator: GeneratorItem, config: GcloudConnectionConfigItem)?) {
        self.model = model
        self.editing = editing
        name = editing?.generator.name ?? ""
        candidateSDKPath = editing?.config.sdkPath
    }

    var isEditing: Bool { editing != nil }
    var hasVerifiedLogin: Bool { login != nil }
    var operatorEmail: String? { login?.config.accountEmail ?? editing?.config.accountEmail }
    var connectedSDKPath: String? { login?.config.sdkPath ?? editing?.config.sdkPath }
    var savedSignInWarning: String? { login == nil ? currentGenerator?.warning : nil }
    var signInTitle: LocalizedStringKey {
        isEditing || hasVerifiedLogin ? "Sign in again" : "Sign in with Google"
    }
    var canSignIn: Bool { sdk != nil && !signingIn && !saving && !isStaleEdit }

    var problem: String? {
        if isStaleEdit { return String(localized: "This generator changed. Close and reopen it before saving.") }
        if let problem = vaultNameProblem(name) { return problem }
        if signingIn { return String(localized: "Finish or cancel the browser sign-in before saving.") }
        if checkingSDK && hasVerifiedLogin { return String(localized: "Wait for the Google Cloud CLI check to finish.") }
        if !isEditing && !hasVerifiedLogin { return String(localized: "Sign in with Google before saving.") }
        return nil
    }

    private var currentGenerator: GeneratorItem? {
        guard let id = editing?.generator.id else { return nil }
        return model.generators.first { $0.id == id }
    }

    private var isStaleEdit: Bool {
        guard let editing else { return false }
        return currentGenerator?.revision != editing.generator.revision
    }

    func chooseSDK(_ result: Result<URL, Error>) {
        guard !closed && !checkingSDK && !signingIn && !saving else { return }
        switch result {
        case let .success(url):
            if let login, login.config.sdkPath != url.path { clearVerifiedLogin() }
            candidateSDKPath = url.path
            checkSDK()
        case let .failure(error):
            sdkError = error.localizedDescription
        }
    }

    func checkSDK() {
        guard !closed && !checkingSDK && !signingIn && !saving else { return }
        checkingSDK = true
        sdk = nil
        sdkError = nil
        let path = candidateSDKPath
        Task {
            defer { if !closed { checkingSDK = false } }
            do {
                let checked = try await model.gcloudCheckSdk(path: path)
                guard !closed else { return }
                if let login, login.config.sdkPath != checked.path { clearVerifiedLogin() }
                sdk = checked
            } catch {
                guard !closed else { return }
                sdkError = error.localizedDescription
            }
        }
    }

    func signIn() {
        guard !closed && canSignIn, let sdk else { return }
        let operation = UUID()
        loginOperation = operation
        signingIn = true
        loginError = nil
        saveError = nil
        Task {
            defer {
                if loginOperation == operation {
                    loginOperation = nil
                    signingIn = false
                }
            }
            do {
                let id = try await model.gcloudBeginLogin(sdkPath: sdk.path)
                // A close or cancel can race the initial call returning the session ID.
                guard loginOperation == operation else { discardLogin(id); return }
                pendingLoginID = id
                let identity = try await model.gcloudFinishLogin(sessionID: id)
                guard loginOperation == operation else { return }
                pendingLoginID = nil
                clearVerifiedLogin()
                login = (id, GcloudConnectionConfigItem(
                    sdkPath: sdk.path, accountSubject: identity.subject, accountEmail: identity.email
                ))
            } catch {
                guard loginOperation == operation else { return }
                if let pendingLoginID { discardLogin(pendingLoginID) }
                pendingLoginID = nil
                loginError = error.localizedDescription
            }
        }
    }

    func cancelSignIn() {
        loginOperation = nil
        signingIn = false
        if let pendingLoginID {
            self.pendingLoginID = nil
            discardLogin(pendingLoginID)
        }
    }

    func keepSavedSignIn() {
        guard !closed && isEditing && !signingIn && !saving else { return }
        clearVerifiedLogin()
        loginError = nil
        saveError = nil
    }

    func close() {
        guard !closed else { return }
        closed = true
        cancelSignIn()
        // Save owns the staged session while it is in flight.
        if !saving { clearVerifiedLogin() }
    }

    private func clearVerifiedLogin() {
        guard let login else { return }
        self.login = nil
        discardLogin(login.id)
    }

    private func discardLogin(_ id: String) {
        Task { [model] in try? await model.gcloudCancelLogin(sessionID: id) }
    }

    func save(onSuccess: @escaping () -> Void) {
        guard !closed && !saving && problem == nil, let config = login?.config ?? editing?.config else { return }
        let draft = GeneratorDraftItem(
            id: editing?.generator.id, name: name.trimmingCharacters(in: .whitespacesAndNewlines),
            config: .gcloudConnection(config),
            credentials: login.map { .gcloudSession(sessionID: $0.id) } ?? .keep
        )
        saving = true
        saveError = nil
        Task {
            do {
                let saved = try await model.saveGenerator(draft)
                login = nil
                guard !closed else { return }
                if let warning = saved.warning {
                    savedWarning = warning
                    showingSaveWarning = true
                } else {
                    onSuccess()
                }
            } catch {
                saving = false
                if closed {
                    clearVerifiedLogin()
                } else {
                    saveError = error.localizedDescription
                }
            }
        }
    }
}

private struct GcloudSDKSection: View {
    let state: GcloudConnectionSetup
    let locateSDK: () -> Void

    var body: some View {
        Section("1. Check the Google Cloud CLI") {
            Link("Install Google Cloud CLI for macOS", destination: URL(string: "https://cloud.google.com/sdk/docs/install")!)
            Text("Install it on this manager Mac. Paired hosts don’t need it to acquire ASM credentials.")
                .font(.callout).foregroundStyle(.secondary)
            HStack {
                Button("Check again", action: state.checkSDK)
                Button("Locate gcloud…", action: locateSDK)
                if state.checkingSDK {
                    ProgressView().controlSize(.small).accessibilityLabel("Checking the Google Cloud CLI")
                }
            }
            .disabled(state.checkingSDK || state.signingIn)
            if let sdk = state.sdk {
                LabeledContent("Checked executable") {
                    VStack(alignment: .trailing, spacing: 2) {
                        Text(sdk.path).monospaced().textSelection(.enabled)
                        Text("Google Cloud CLI \(sdk.version)").foregroundStyle(.secondary)
                    }
                }
            }
            if let error = state.sdkError {
                Text(error).textSelection(.enabled)
                Text("In the file picker, press ⌘⇧G to enter the path to the installed SDK’s gcloud executable.")
                    .font(.callout).foregroundStyle(.secondary)
            }
        }
    }
}

private struct GcloudSignInSection: View {
    let state: GcloudConnectionSetup

    var body: some View {
        Section {
            Text("gcloud opens this Mac’s browser. Complete Google’s consent prompts and check which account was verified. If Google requires administrator approval, ask your administrator.")
                .font(.callout).foregroundStyle(.secondary)
            HStack {
                if state.signingIn {
                    ProgressView().controlSize(.small).accessibilityHidden(true)
                    Text("Waiting for browser sign-in…")
                    Button("Cancel sign-in", action: state.cancelSignIn)
                } else {
                    Button(state.signInTitle, action: state.signIn).disabled(!state.canSignIn)
                    if state.isEditing && state.hasVerifiedLogin {
                        Button("Keep saved sign-in", action: state.keepSavedSignIn)
                    }
                }
            }
            if let email = state.operatorEmail {
                LabeledContent(state.hasVerifiedLogin ? "Verified Google account" : "Saved Google account") {
                    Text(email).textSelection(.enabled)
                }
            }
            if let path = state.connectedSDKPath, path != state.sdk?.path {
                LabeledContent("SDK for this sign-in") { Text(path).monospaced().textSelection(.enabled) }
            }
            if let warning = state.loginError ?? state.savedSignInWarning {
                Text(warning).textSelection(.enabled)
            }
            if state.isEditing {
                Text("Renaming preserves existing leases. Saving a new sign-in ends them, but does not remove any provisioned Google Cloud resources. See Activity for cleanup details.")
                    .font(.callout).foregroundStyle(.secondary)
                Link("Review or withdraw Google consent…", destination: GcloudGeneratorSheet.accountPermissionsURL)
            }
        } header: {
            Text("2. Sign in with Google")
        } footer: {
            Text("ASM uses private CLI settings and saves its credential in the login keychain only when you save. Your usual gcloud settings and Application Default Credentials stay unchanged.")
        }
    }
}

private struct GcloudConnectionUsageSection: View {
    var body: some View {
        Section("After you save") {
            Text("Saving connects your Google account. It does not change IAM, create a service account, or issue a token. Requests supply a project and permissions using `--project` and `--permissions`.")
            Text("On first use, the permission popup shows the service account and project-level IAM roles it needs. Approve creates that access and grants the lease; Deny does neither. Google Cloud keeps the account and bindings after the lease ends.")
            Text("To view accounts created by ASM and their dependent leases, open Google Service Accounts in Generator settings.")
            Text("Agents receive short-lived service account tokens, not your Google sign-in. gcloud reads `CLOUDSDK_AUTH_ACCESS_TOKEN`; other clients may need explicit bearer-token support.")
        }
        .font(.callout)
    }
}

struct GcloudLegacyGeneratorSheet: View {
    let generator: GeneratorItem
    let config: GcloudConfigItem
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Section("Legacy Google Cloud generator") {
                    LabeledContent("Name") { Text(generator.name) }
                    Text("This read-only configuration stays bound to its saved service account, project, and OAuth scope ceiling. To use project and permission requests, add a separate Google Cloud connection.")
                        .font(.callout).foregroundStyle(.secondary)
                    LabeledContent("Google sign-in account") { Text(config.accountEmail).textSelection(.enabled) }
                    LabeledContent("SDK executable") { Text(config.sdkPath).monospaced().textSelection(.enabled) }
                    if let warning = generator.warning { Text(warning).textSelection(.enabled) }
                }
                GcloudLegacyAuthoritySection(config: config)
            }
            .formStyle(.grouped)
            HStack {
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
            .padding()
        }
        .frame(minWidth: 580, idealWidth: 640, maxWidth: 760, minHeight: 440, idealHeight: 560)
    }
}

private struct GcloudLegacyAuthoritySection: View {
    let config: GcloudConfigItem

    var body: some View {
        Section {
            LabeledContent("Quota project") { Text(config.projectID).textSelection(.enabled) }
            LabeledContent("Project number") { Text(config.projectNumber).monospaced().textSelection(.enabled) }
            LabeledContent("Service account") { Text(config.ceiling.serviceAccountEmail).textSelection(.enabled) }
            LabeledContent("Service account unique ID") {
                Text(config.ceiling.serviceAccountUniqueID).monospaced().textSelection(.enabled)
            }
            VStack(alignment: .leading, spacing: 4) {
                Text("Saved OAuth scope ceiling").font(.subheadline.weight(.semibold)).accessibilityAddTraits(.isHeader)
                ForEach(config.ceiling.scopes, id: \.self) { uri in
                    Text(uri).monospaced().textSelection(.enabled)
                }
            }
        } header: {
            Text("Bound authority")
        } footer: {
            Text("The quota project and OAuth scopes do not create a resource boundary. IAM grants may change independently of ASM.")
        }
    }
}
