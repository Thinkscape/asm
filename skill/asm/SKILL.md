---
name: asm
description: Get API keys, tokens and passwords through Agents Secrets Manager (asm): request a lease, use the sentinel through the proxy, never print secret values.
---

# Agents Secrets Manager (`asm`)

## 1. What it is

Secrets live on the operator's Mac. A human approves every request you make. You normally
receive a **sentinel** (`asm_…`), not the value. The sentinel works only when the request
goes through the asm proxy, only over HTTPS, and only to the hosts the operator approved;
the proxy swaps it for the real value on the way out.

## 2. Setup

```bash
asm doctor                                  # every line should say ok
eval "$(asm proxy-info | grep '^export')"   # in the shell that runs commands needing secrets
```

`doctor` prints `FAIL paired` when this machine is not paired: ask the operator to pair it
(`asm pair <manager-host> [code]`). The exports set `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`,
`NO_PROXY` and the CA bundle variables (`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`,
`CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `NODE_EXTRA_CA_CERTS`).

## 3. Finding secrets

```bash
asm list            # one name per line
asm list --json     # with vault, kind, fields and any active lease
```

Names may be vault-prefixed (`work/GITHUB_TOKEN`) when two vaults hold the same name; use
the name exactly as listed.

## 4. Requesting

```bash
asm get --hosts api.github.com GITHUB_TOKEN "Open a PR on acme/web for the login fix the user asked for; needs GitHub API"
```

- The reason must let a human make an informed decision: what you are doing, why this
  secret, which service. At most 250 characters.
- Request only the hosts you will call: `api.example.com`, or `*.example.com` for a domain
  and its subdomains. Broad patterns get flagged to the operator.
- The command waits up to 120 s (`--wait SECS`) and then prints:

  ```
  mode: sentinel
  hosts: api.github.com
  expires: 2026-11-16T12:34:56Z
  /run/user/1000/asm/secrets/GITHUB_TOKEN
  ```

- Use the printed paths, never the content:
  `curl -H "Authorization: Bearer $(cat /run/user/1000/asm/secrets/GITHUB_TOKEN)" https://api.github.com/user`
- Never print a secret file into the conversation (no `cat` to the terminal, no `echo`).

## 5. Outcomes

- Read the `hosts:` line: the operator may have changed the hosts you asked for. `*` means
  any host.
- `denied: host selection too open` (exit 3): narrow `--hosts` and ask again.
- `denied: provide a better reason` (exit 3): rewrite the reason so a human can judge it.
- `denied: <other text>`: follow it; do not retry the same request.
- Exit 4 (`pending: …`): the operator has not answered yet; run the same command again to
  keep waiting.
- HTTP 403 `asm: sentinel not valid for this host or scheme`: the host is not approved for
  this lease, or the URL is not HTTPS, or the lease has ended.
- `request lost; run the command again`: the manager restarted; repeat the command.
- Never ask for a secret value in chat.

## 6. Raw values

`asm get --raw NAME "REASON"` asks for the real value. Use it only for tools that cannot go
through the proxy (database clients, SSH, non-HTTP protocols). The operator may still return
a sentinel (`mode: sentinel`). Pass the file by path or `$(cat …)`; never print it.

## 7. Changing secrets

```bash
printf '%s' "$NEW_VALUE" | asm update [--field password] NAME   # needs approval
printf '%s' "$VALUE" | asm add NAME                              # needs approval
```

Both read the value from stdin. `add` creates the secret but no lease: run `asm get`
afterwards. After an `update`, raw leases on that secret are revoked, so request again;
sentinel leases keep working with the new value.

## 8. Limits

- Sentinels are substituted in headers, the URL path, the query and request bodies up to
  10 MB; larger bodies get HTTP 413.
- Not substituted on WebSocket connections (403).
- Use hostnames, not IP addresses, for HTTPS.
- `*.username` files hold the plain username, not a sentinel.
- Echoed secrets in responses are redacted on a best-effort basis; do not rely on it.
- Secret files disappear when their leases end.
