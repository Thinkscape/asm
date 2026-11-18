---
name: asm
description: "Request access to secrets such as API keys, access tokens, login credentials, certificates, GitHub CLI tokens, and gcloud tokens. Use them in commands as environment variables or files."
---

# Agents Secrets Manager (`asm`)

This skill ships inside the `asm` binary. `asm skill install` writes it to
`~/.agents/skills/asm/SKILL.md` (`--dir DIR` for other skill folders); run it again after
upgrading `asm` to keep this file in step with the CLI.

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
   Acquisitions are sequential in input order. Every acquisition must succeed before the
   child starts; approval is not an atomic multi-lease transaction.
4. **Follow the decision.** First generated access needs approval of the app, repositories,
   permissions, delivery mode and lease duration. Later invocations may reuse or renew
   that grant. Static sentinel access can reuse a compatible lease; static raw access
   requires approval on every invocation.

Generated GitHub credentials default to **raw**; static secrets default to **sentinel**.
`--raw` asks for values but the operator may choose sentinel delivery. `--sentinel`
forbids raw disclosure. Global `--raw`, `--sentinel` and `--hosts` apply to every exec binding.
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
asm get --repositories acme/web --sentinel --hosts api.github.com GH_TOKEN 'Read repository metadata through the proxy'
asm get --lease LEASE_ID GH_TOKEN 'Continue reading acme/web'
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
- `get --lease LEASE_ID --refresh ...` intentionally rotates and revokes earlier known
  tokens; it can disrupt running consumers. Routine renewal leaves predecessor copies
  usable until their natural expiry.
- Exec acquires before launch and checks ten minutes of provider-token headroom. It does
  not refresh a running child, revoke on child exit, or update files previously written
  by get. Rerun get to synchronize file views.
- Expired raw generated material is removed while lease reservations remain. A missing
  file can mean token expiry, not lease expiry. Re-run get instead of rereading the path.

Exec's `--wait` is one acquisition deadline across requests and launch-time lease checks.
Discovery, proxy/CA preparation and child runtime are outside that budget. A failed
acquisition starts no child; approvals already granted remain.

## Sentinel use outside exec

```bash
eval "$(asm proxy-env)"
asm proxy-info
```

Run proxy-env in the shell that will use sentinel files. It exports proxy and CA variables;
`--unset` removes them, and fish users add `--shell fish`. It fails if no proxy is reachable.
`FAIL firewall` means the operator must repair the Mac's firewall rule; do not bypass it.
Verify GitHub App access against `repos/OWNER/REPO`, not `/user`:

```bash
asm exec --repositories acme/web GH_TOKEN -- gh api repos/acme/web
asm exec --repositories acme/web --sentinel --hosts api.github.com GITHUB_TOKEN -- gh api repos/acme/web
```

Sentinels are restricted to approved HTTPS hosts. Request only needed hosts; broad
wildcards are flagged. Substitution covers headers, paths, query and bodies up to 10 MB.
Larger bodies receive 413; WebSockets are unsupported. Use hostnames, not IP addresses.
Response redaction is best effort.

## Outcomes and safety

- Denial (exit 3): follow the operator's reason. Narrow hosts or improve the reason if
  requested; do not automatically repeat an unchanged denied request.
- Pending timeout (exit 4): run the same command again to continue waiting. Acquisition
  deadline exhaustion in exec starts no command.
- Unknown network outcome (exit 1): the request may remain pending; repeating can recover it.
- Ended pinned lease: request a new lease without `--lease`. Unavailable generation:
  report the error; do not switch apps, scope or delivery mode to bypass it.
- Restart/lost request: repeat the command. Generated grants restart without token material;
  explicit get/exec can mint under surviving authorization.

Raw exec avoids credential files, argv and ASM stdout, but the child receives values in
memory/environment and can expose them. Avoid tracing, environment dumps and commands that
print credentials. Never ask for or paste secret values in chat.

Revocation attempts to revoke every known generated token at GitHub. Failed revocation
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
