---
name: asm
description: "Request access to secrets such as API keys, access tokens, login credentials, certificates, GitHub CLI tokens, and gcloud tokens. Use them in commands as environment variables or files."
---

# Agents Secrets Manager (`asm`)

This skill ships inside the `asm` binary. `asm skill install` writes it to
`~/.agents/skills/asm/SKILL.md` (`--dir DIR` for other skill folders); run it again after
upgrading `asm` to keep this file in step with the CLI. Setting up a machine or a browser,
reinstalling and fixing failures are covered in `SETUP.md` next to this file.

## Workflow

1. **Pair.** Run `asm doctor`. If unpaired, ask the operator to pair this machine with
   `asm pair <manager-host> [code]`. Pairing authorizes the host; `ASM_AGENT` is attribution
   and routing affinity, not isolation from another agent on the same host.
2. **Discover.** Run `asm list --json` for addressable names, aliases, fields and leases.
   Fields are exact metadata names, not JSONPath. Use qualified names when outputs collide.
3. **Launch with credentials**, preferably without files:

   ```bash
   asm exec --repositories acme/web --permissions pull_requests=read GH_TOKEN -- gh pr list --repo acme/web
   asm exec --repositories acme/web 'GH_TOKEN,OTHER_SECRET' -- my-command
   ```

   GitHub Apps expose `GH_TOKEN` and `GITHUB_TOKEN` as aliases of one credential. Bare
   shorthand replaces both inherited variables together; requesting both acquires once.
   For generated GitHub tokens, pass `--repositories OWNER/REPO` to `exec` and `get`,
   except when pinning an existing lease with `get --lease ID`. Omitted permissions
   mean `metadata=read`; request additional levels with `--permissions key=level[,key=level]`.
   Request multiple repos with a comma-separated list only when one installation covers them.
   Otherwise split the work into separate commands. The repo selects the installation;
   qualify the token name only when you need a particular app.
   For Google Cloud connections, pass `--project PROJECT_ID` and `--permissions CLAIM[,CLAIM...]`
   to `get` or `exec`. Use `CLOUDSDK_AUTH_ACCESS_TOKEN`, or qualify it as
   `gcloud-dev/CLOUDSDK_AUTH_ACCESS_TOKEN` to select a particular connection. Example:
   `asm exec --project my-staging-project --permissions compute=read CLOUDSDK_AUTH_ACCESS_TOKEN -- gcloud compute instances list --project=my-staging-project`.
   Do not bind a bearer token to `GOOGLE_APPLICATION_CREDENTIALS` (it expects a file).
   Acquisitions are sequential in input order. Every acquisition must succeed before the
   child starts; approval is not an atomic multi-lease transaction.
4. **Follow the decision.** First generated access needs approval of the identity, scope,
   and lease duration. Request only what the task needs. The operator may
   narrow or extend the grant within one GitHub installation or one Google project.
   Use the **approved grant**, not the original flags, to determine what was granted.
   On first use of a Google profile, approval also authorizes the IAM setup shown.
   Later invocations may reuse or renew that grant. Static sentinel access can reuse a compatible lease; static raw access
   requires approval on every invocation.

GitHub and Google generators deliver **raw tokens only**. Omit `--sentinel` and `--hosts` for generated tokens. Static secrets default to **sentinel**; `--sentinel` forbids raw disclosure. For a command that needs both kinds, `--hosts` applies only to the static fields.
Give a specific `--reason` when the executable name alone does not explain the task.

For substituted fields, exec configures the proxy and public CA files automatically.
Plain-only selections, such as a login username, need neither destination hosts nor proxy
setup. Raw-only exec inherits the caller's networking. An unavailable proxy aborts a
sentinel launch; it does not fall back to raw.

## Binding reference

Grammar: `[DEST=]SOURCE[::FIELD]`. `get` takes one binding followed by a reason;
`exec` takes a comma-separated binding list followed by literal `--` and command arguments.
Arguments are passed directly, not interpreted by a shell.

- `DEST` is a caller-chosen environment name for exec or local filename for get.
- A single-field source can use shorthand; its actual field is discovered from metadata.
  A multi-field exec source requires `DEST=SOURCE::FIELD`.
- Whole-item `get SOURCE REASON` retains normal field-based files.
- Dots are literal. Backslash escapes the next character; single-quote the whole binding
  or list so the shell preserves those escapes.

```bash
asm exec --raw 'GOOGLE_USER=Vaultwarden/google::username,GOOGLE_PASS=Vaultwarden/google::password' -- my-command
asm get 'GOOGLE_USER=Vaultwarden/google::username' 'Sign in'
asm get 'Vaultwarden/google::username' 'Sign in to the requested site'
asm exec --repositories acme/web 'BOT_A_TOKEN=release-bot/GH_TOKEN,BOT_B_TOKEN=review-bot/GH_TOKEN' -- my-command
asm get 'NAME=work/item\,with\,commas::field' 'Use the selected field'
asm get 'NAME=work/item\:\:literal::value' 'Use the selected value'
```

The login exec groups both fields into one field-limited approval. Because it requests
static raw values, later runs prompt again. The username-only get delivers only username
to `GOOGLE_USER` or its reported collision-suffixed path.

Explicit destinations set only themselves. Prefer bare GitHub shorthand for gh so stale
inherited `GH_TOKEN` and `GITHUB_TOKEN` cannot disagree. Custom `BOT_A_TOKEN`/`BOT_B_TOKEN`
may use different apps; binding the two standard GitHub variables to different generated
identities is rejected before acquisition.

Legacy get names containing delimiters are not silently reinterpreted. If literal `A=b`
exists, `asm get 'A=b' ...` is ambiguous: use `asm get 'A\=b' ...` for that item or qualify
the intended source/binding. Escape literal `::` as `\:\:` and literal backslash as `\\`.
Unknown fields, ambiguous names, destination conflicts and malformed bindings fail locally.
If the manager lacks field/generator capabilities, upgrade it rather than dropping flags.

## Files and renewal

```bash
asm get --repositories acme/web GH_TOKEN 'Inspect repository metadata'
asm get --repositories acme/web --permissions contents=read GH_TOKEN 'Read repository contents'
asm get --lease LEASE_ID GH_TOKEN 'Continue reading acme/web'
asm get --project my-staging-project --permissions storage=read CLOUDSDK_AUTH_ACCESS_TOKEN 'Read staging objects'
```

Use reported paths, selected app/grant, mode and deadlines; never print file contents.
Generated aliases share a lease and credential version. A later get updates all known
local file views of the returned field, including both GitHub aliases; subset static gets
leave other fields intact. Explicit destinations are local delivery metadata, not grants.

The **lease deadline** ends authorization; the **credential deadline** ends one provider
token. GitHub tokens last about an hour. A 12-hour lease allows on-demand renewal of the
same app and approved grant without another approval, not a 12-hour token.

- Repeat get or exec to renew. `--lease` pins an owned generated lease across name changes
  and collisions; it cannot extend or rebind an ended lease.
- `--new-lease` requests a fresh operator decision. Changing requested scope may also
  require approval; renewal always retains the actual approved grant.
- `get --lease LEASE_ID --refresh ...` rotates the credential. GitHub attempts to revoke
  known predecessors, which can disrupt running consumers. Google tokens cannot be
  individually revoked: copies remain usable until expiry even after the lease ends.
- Exec acquires before launch and checks ten minutes of provider-token headroom. It does
  not refresh a running child, revoke on child exit, or update files previously written
  by get. Rerun get to synchronize file views.
- Expired raw generated material is removed while lease reservations remain. A missing
  file can mean token expiry, not lease expiry. Re-run get instead of rereading the path.

Exec's `--wait` is one acquisition deadline across requests and launch-time lease checks.
Discovery, proxy/CA preparation and child runtime are outside that budget. A failed
acquisition starts no child; approvals already granted remain.

## GitHub CLI (`asm gh`)

On a machine where `asm gh install` put its `gh` shim first on `PATH` (`asm gh status` shows
it), plain `gh` works for the repositories the operator added with `asm gh repo add`: the
shim attaches that owner's approved GitHub App token. Don't wrap those commands in `asm exec`.

- `asm gh status` lists the repositories and permissions. For another repository or more
  permissions, run `asm gh repo add OWNER/REPO [--permissions KEY=LEVEL]` (the operator
  approves the owner's whole set), or use `asm exec … GH_TOKEN -- gh …` for a one-off task.
  A command run with `GH_TOKEN` already set goes to the real `gh` unchanged.
- `asm gh: … waiting for the operator's approval` (exit 4): the lease ended or was never
  approved. Ask the operator to approve it, then rerun; don't loop.
- `asm gh: the operator denied …` (exit 3): don't retry; tell the user.
- `HTTP 403 … Resource not accessible by integration`: the token lacks that permission or
  repository. It is not a sign-in problem; never run `gh auth login`.
- `gh auth token` prints a live token: never print, log or paste it.

## Sentinel use outside exec

```bash
eval "$(asm proxy-env)"
asm proxy-info
```

Run proxy-env in the shell that will use sentinel files. It exports proxy and CA variables;
`--unset` removes them, and fish users add `--shell fish`. It fails if no proxy is reachable.
`FAIL firewall` means the operator must repair the Mac's firewall rule; do not bypass it.

Sentinels are restricted to approved HTTPS hosts. Request only needed hosts; broad
wildcards are flagged. Substitution covers headers, paths, query and bodies up to 10 MB.
Larger bodies receive 413; WebSockets are unsupported. Use hostnames, not IP addresses.
Response redaction is best effort.

## Browser logins

Sign in to websites in a browser you drive (the user's Chrome, T3 Code preview tabs,
OpenBot agents) without ever seeing the password. Run every browser-login `asm` command on
the machine where that browser runs.

**Setup** happens once per machine and browser: `asm browser install chrome|t3code|openbot`,
then restart that browser. `asm browser status` shows what is installed. For per-browser
steps, reinstalling, the proxy router and fixing failures, read `SETUP.md` next to this file
(`asm skill install --print-setup` prints it).

Already signed in? Do nothing. Otherwise:

1. Find the URL the credentials are posted to. For a plain HTML form it is
   `document.querySelector('input[type=password]').form.action`. Most sites sign in with
   JavaScript instead (the form has no `action`, or `form.action` is just the page URL): the
   password then goes to an API URL, often on another host (for example
   `https://clerk.example.com/v1/client/sign_ins?...`). Find it in your browser tool's
   network log after submitting once with a made-up email address and password (never the
   real username), and use that exact URL, query string included. The sentinel only works
   at that URL; sent anywhere else it is wasted and the site sees a wrong password.
2. `asm get --login-url <that URL> --reason "<why>"` (pass the vault ITEM name when asked,
   when several logins match, or when the API host differs from the item's site). It first
   checks that the URL's host went through this machine's asm proxy router in the last 30
   minutes, which step 1 does when the browser is set up. It prints the username, a
   single-use password sentinel and, when the item has an authenticator key, a one-time code.
3. Open or reload the login page, type the username and the sentinel, submit **once**.
4. At a one-time-code prompt, run `asm get <ITEM>::totp --reason "<why>"` (no popup while
   the grant lasts) and type the code.
5. A password field with `maxlength` under 44, or one input box per OTP digit: use
   `asm login <URL> --reason "<why>"` instead. The operator signs in on the Mac and you
   receive a storage-state file to load into your browser tool. When the site signs in
   through a separate service host (the API URL from step 1 is on another host, such as
   `clerk.example.com`), add `--fill-origin https://<that host>` so its session cookies
   come along; without them the site signs you out again.

| Error | Action |
|---|---|
| `no browser on this machine has sent HOST through the asm proxy router` | Do step 1 in the browser you will sign in with, then retry. Still failing: that browser isn't set up (`asm browser status`, `SETUP.md`). |
| `403 login sentinel not valid for METHOD URL` | Re-request with that URL. |
| `403 login sentinel must be an entire form or JSON value` | Type the sentinel alone into the password field. |
| `403 login body must be …` or `one login grant per request` | Use `asm login`. |
| `403 sentinel expired or revoked` | Already used or ended; request a new grant. |
| `403 this login grant belongs to another machine` | Request it on the browser's machine. |
| `503 login secret unavailable` | The vault is locked; tell the operator. |
| `ERR_TUNNEL_CONNECTION_FAILED` on a third-party host | Not caused by the grant: that host is unreachable from this machine (often a DNS ad-block). Ignore it unless the sign-in needs it. |
| Anything else (`502 asm proxy-router: …`, certificate errors, every HTTPS page failing, `T3 updated its browser`) | Run `asm doctor` and follow `SETUP.md`, section "Diagnose and fix". |

## Outcomes and safety

- Denial (exit 3): follow the operator's reason. Narrow hosts or improve the reason if
  requested; do not automatically repeat an unchanged denied request.
- Pending timeout (exit 4): run the same command again to continue waiting. Acquisition
  deadline exhaustion in exec starts no command.
- Unknown network outcome (exit 1): the request may remain pending; repeating can recover it.
- Ended pinned lease: request a new lease without `--lease`. Unavailable generation:
  report the error; do not switch apps, scope or delivery mode to bypass it.
- Manager restart: keep polling the same pending request. An unexpired generated token or sentinel remains valid under its existing lease; restart does not require `--refresh`.

Raw exec avoids credential files, argv and ASM stdout, but the child receives values in
memory/environment and can expose them. Avoid tracing, environment dumps and commands that
print credentials. Never ask for or paste secret values in chat.

For a GitHub grant, revocation attempts to revoke every known installation token. Failed revocation
or a manager crash can leave delivered raw copies usable until provider expiry; raw
recall is not guaranteed. Sentinel delivery withholds the token and allows local blocking;
the proxy's parent-death watchdog stops forwarding when the manager exits.

File cleanup normally runs through the background reaper at expiry and shortly after
revocation. `get --no-reaper` or `ASM_NO_REAPER=1` disables that process; later file-aware
commands perform cleanup. File-free exec never starts a reaper or reconciles secret files.

## Changing static secrets

```bash
printf '%s' "$NEW_VALUE" | asm update --field password NAME
printf '%s' "$VALUE" | asm add NAME
```

Both require approval and read values from stdin. Add creates no lease; request access
afterwards. Update revokes static raw leases and refreshes existing sentinel substitution.
Generated secrets cannot be updated; their app configuration and approved claims control issuance.
