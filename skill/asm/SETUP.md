# asm setup and troubleshooting

Companion to the asm skill (`SKILL.md` next to this file; `asm skill install --print-setup`
prints this file). Use it to set up a machine, to reinstall after an upgrade, and to diagnose
failures. Run every command on the machine it names, as the user that runs the browser or
agent there. Ask the operator when a step needs the manager Mac, `sudo`, or a password.

## 1. Pair and check

```bash
asm --version                 # the CLI; upgrade it before anything else
asm pair <manager-host>       # once per machine and user; the operator approves the code
asm doctor                    # every line ok? Fix FAIL lines first
asm skill install             # refresh this skill after upgrading asm
```

`asm doctor` checks pairing, the manager, the proxy and, after `asm browser install`, the
proxy router and each installed browser. Each FAIL line ends with `fix: <command>`.

## 2. How browser logins fit together

- **Login grant:** `asm get --login-url URL` delivers the username, a single-use password
  sentinel and the current one-time code. The manager's proxy swaps the sentinel for the
  real password only in one HTTPS POST/PUT/PATCH to exactly that URL.
- **Proxy router** (`asm proxy-router`, `127.0.0.1:7418`): the browser sends all HTTPS to
  it. A site with an active login grant goes to the manager's proxy; everything else goes
  straight to the site, untouched. Plain HTTP never uses the router.
- **Browser CA:** the asm browser CA, trusted once per browser. The proxy issues
  certificates from it only for a granted site.
- **Same machine:** request grants on the machine where the browser runs. Only that
  machine's router knows the route.
- **No router, no HTTPS:** while the router is down, HTTPS fails in configured browsers
  instead of bypassing asm.

## 3. Install per environment

Every install saves the browser CA, installs the router as a user service (systemd user
unit `asm-proxy-router.service` on Linux, LaunchAgent `com.thinkscape.asm.proxy-router` on
macOS) and records itself in `~/.config/asm/browsers.json`. `--no-service` skips the service;
then run `asm proxy-router run` under your own supervisor (section 4). `--port N` picks
another router port. Reinstalling is always safe and is the fix for most problems.

### Google Chrome or another Chromium (Linux, macOS)

```bash
asm browser install chrome                         # profile "Default" of Chrome's user data dir
asm browser install chrome --profile "Work"        # by folder or display name
asm browser install chrome --user-data-dir DIR     # Chromium, Brave, Playwright profiles, ...
```

- Quit that browser first; install refuses while it runs. Restart it afterwards.
- It writes a CA row into the profile's `ServerCertificate` database and a `proxy`
  preference (PAC: `https:` and `wss:` to the router) into its `Preferences`. Other
  profiles are untouched.
- Every HTTPS page of that profile then depends on the router.
- Refused when the profile, the system (macOS) or `HTTPS_PROXY` already sets a proxy:
  asm can't chain proxies.
- Tools that drive this Chrome (the Codex Chrome extension, chrome-devtools-mcp, the omp
  relay) need nothing else.

### T3 Code preview tabs

```bash
asm browser install t3code                     # Linux; needs certutil (libnss3-tools / nss-tools)
asm browser install t3code --trust-user-wide   # macOS: trusts the CA in the login keychain
```

- Wraps every downloaded version of T3's `chrome-headless-shell` (under
  `~/.t3/tools/chrome-headless-shell/`, or `$T3CODE_HOME/...`). The real binaries move to
  `asm-real/<version>/` there; the wrapper adds `--proxy-server=https=127.0.0.1:7418`. On
  Linux the CA goes into a private NSS database under `~/.config/asm/browser/t3code`.
- Applies to all T3 preview tabs on the machine. There is no profile to choose.
- **T3 downloads a new browser version with some T3 updates and starts it unwrapped.**
  `asm browser status`, `asm doctor` and `asm get --login-url` then say `T3 updated its
  browser to <version>`. Fix: run `asm browser install t3code` again.
- Takes effect when T3 next starts its browser: it closes an idle one after 5 minutes.
  Check: `pgrep -fa 'chrome-headless-shell --'` shows `.../asm-real/<version>/...` with
  `--proxy-server`.

### OpenBot

OpenBot's browsers run where the OpenBot **server** runs: on the desktop Mac for a local
server, or on the server host (for example a Linux box running `openbot.service` as user
`openbot`). Install there, as that user. OpenBot trusts only the OS store, so the CA is
trusted user-wide: `~/.pki/nssdb` (else `~/.local/share/pki/nssdb`) on Linux, the login
keychain on macOS.

```bash
asm browser install openbot --trust-user-wide              # run it in a terminal
asm browser install openbot --trust-user-wide --restart    # scripts: quit and restart OpenBot without asking
asm browser install openbot --trust-user-wide --data-dir DIR   # another server data dir (repeatable)
```

The install routes the **Shared** and **agent-only** browser sessions itself (macOS and
Linux). OpenBot ignores and later overwrites these settings when they change while it runs,
so asm writes them while OpenBot is stopped:

- **OpenBot desktop app running:** in a terminal asm asks `Quit OpenBot now and start it
  again afterwards? [Y/n]`. Yes: asm quits it (OpenBot stops its agents first), writes the
  settings and starts it again. No: asm waits until you quit OpenBot, writes, and asks you to
  start it again. Without a terminal, add `--restart`, or the install refuses
  (`OpenBot is running (pid N): quit it and run this again, or add --restart …`).
- **OpenBot as a system service (Linux):** asm waits while you run
  `sudo systemctl stop openbot.service` in another shell, writes, and asks you to run
  `sudo systemctl start openbot.service`. Without a terminal it refuses with those commands.
- **From an OpenBot agent's shell:** refused (`this command runs inside OpenBot …; run it in
  a terminal instead`): quitting OpenBot would end the command itself.
- After OpenBot is back, asm re-reads the settings and confirms: `OpenBot is running again
  (pid N) with asm's browser settings: Shared, agent "…" route HTTPS through asm's proxy
  router.` If OpenBot isn't back within 60 s after `--restart`/Yes, asm says so; start it
  yourself.
- Refusals (another proxy, no terminal) come before asm changes anything.

What the install routes:

- It finds the server data directories: OpenBot's own (`~/Library/Application
  Support/OpenBot` on macOS, `${XDG_CONFIG_HOME:-~/.config}/OpenBot` on Linux) when it has
  an `openbot.db`, plus each local server under its `local-servers/`. `--data-dir` replaces
  that search. No server data means this machine is only a client of a remote OpenBot
  server: install on the server; the run then only trusts the CA.
- In each, it writes a `proxy` preference (HTTPS and WSS to the router, HTTP and WS direct)
  into the `Preferences` of the Shared session and of every agent without a named browser
  profile (also agents that don't use their own session yet), keeping all other settings.
- Refused when one of those sessions already has another proxy.
- **Agents created after the install are not routed** until you run the install again;
  `asm browser status`, `asm doctor` and `asm get --login-url` say
  `OpenBot agent "<name>" is not routed`.
- **Named browser profiles** keep OpenBot's own proxy setting. To route one, in OpenBot,
  **Settings → Browser profiles**: add the proxy `http://127.0.0.1:7418`, use it in the
  profile, assign the profile to the agent (agent settings → Advanced → Browser profile)
  and restart OpenBot.

`--ca-only` only trusts the CA and leaves OpenBot's sessions alone (route a named profile as
above, or use the drop-in below).

**Linux server alternative, without stopping OpenBot for each new agent:** OpenBot leaves
the Shared and agent-only sessions on the system proxy, which Chromium reads from the
`auto_proxy` environment variable. Give the OpenBot service the asm PAC and restart it; this
covers every OpenBot browser on that server without a proxy of its own, agents created later
included. Install with `--ca-only` then. Command-line tools ignore `auto_proxy`.

```bash
PAC='function FindProxyForURL(url, host) {
  if (url.substring(0, 6) == "https:" || url.substring(0, 4) == "wss:") return "PROXY 127.0.0.1:7418";
  return "DIRECT";
}'
sudo mkdir -p /etc/systemd/system/openbot.service.d
printf '[Service]\nEnvironment="auto_proxy=data:application/x-ns-proxy-autoconfig;base64,%s"\n' \
  "$(printf %s "$PAC" | base64 -w0)" | sudo tee /etc/systemd/system/openbot.service.d/asm-proxy.conf
sudo systemctl daemon-reload && sudo systemctl restart openbot
```

**Hosted servers:** the service user usually has no login session. Pair and install as that
user with `sudo -u openbot -H asm pair <manager-host>` and
`sudo -u openbot -H asm browser install openbot --trust-user-wide --no-service` (it waits
while you stop `openbot.service`). Then run the router as a system service (section 4).

## 4. The proxy router

| Task | Linux (user service) | macOS (LaunchAgent) |
|---|---|---|
| State | `asm proxy-router status` (`--json`) | same |
| Restart | `systemctl --user restart asm-proxy-router` | `launchctl kickstart -k gui/$UID/com.thinkscape.asm.proxy-router` |
| Logs | `journalctl --user -u asm-proxy-router` | `~/Library/Logs/asm-proxy-router.log` |
| Keep running after logout | `loginctl enable-linger $USER` | — |

The router logs each routed connection (`routed <host>:<port> -> <status>`) and each route it
adds or drops. Direct connections are not logged.

**Without a user session** (hosted servers, containers), install with `--no-service` and run
the router as a system service for that user:

```ini
# /etc/systemd/system/asm-proxy-router-<user>.service
[Service]
User=<user>
Environment=HOME=<that user's home>
ExecStart=/usr/local/bin/asm proxy-router run --port 7418
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now asm-proxy-router-<user>
```

## 5. Diagnose and fix

Start with `asm doctor` and `asm browser status` on the browser's machine.

| Symptom | Cause | Fix |
|---|---|---|
| `asm get --login-url`: `no asm proxy-router on this machine` | Not installed here, or the router is stopped | Install (section 3) or restart the router (section 4) |
| `asm get --login-url`: `no browser on this machine has sent HOST through the asm proxy router` | The browser hasn't loaded the login page in the last 30 minutes, or it bypasses the router (not set up, T3 updated its browser, a new OpenBot agent) | Load the login page in that browser, then retry; still failing: `asm browser status` and the fix it shows |
| `warning: … T3 updated its browser to <v>` | T3 runs a new, unwrapped browser | `asm browser install t3code` |
| Every HTTPS page fails (`ERR_PROXY_CONNECTION_FAILED`) | Router down | Restart it (section 4) |
| `ERR_TUNNEL_CONNECTION_FAILED` for one host | The router could not reach it directly: blocked by DNS (for example a `0.0.0.0` ad-block answer), offline, or refused | Same result as without asm; nothing to fix in asm. Check with `getent hosts <host>` |
| `502 asm proxy-router: cannot reach the asm proxy …` | The manager's proxy is down or unreachable from here | `asm doctor`; ask the operator |
| `502 asm proxy-router: the manager rejected this host's proxy credentials` | Proxy authentication is on and this host's pairing changed | `asm pair <manager-host>` again |
| Certificate error on a granted site | The browser doesn't trust the asm browser CA yet | Restart the browser; `asm browser status`; reinstall |
| `stale CA` in `asm browser status` | The manager's browser CA changed | `asm browser install <target>` |
| `incomplete …` in `asm browser status` | A setting asm wrote was changed or removed | Run the `fix:` command shown |
| `incomplete OpenBot agent "<name>" is not routed` | The agent was created after `asm browser install openbot` | Run the install again in a terminal; it offers to restart OpenBot |
| `403 login sentinel not valid for METHOD URL` | The page posts somewhere other than the granted URL | Request a grant for that exact URL |
| The site reports a wrong password, and the manager's Activity Log has no substitution | The sentinel went straight to the site: wrong URL, or the browser isn't routed | Check the URL in the network log and `asm browser status`; request a new grant |
| The page shows "Sign in not loaded yet" or similar | Submitted before the page's sign-in script loaded | Wait until the page has fully loaded, then submit once |
| A handed-over `asm login` session signs out at once | The site keeps its session on a separate sign-in host (Clerk, Auth0) | `asm login … --fill-origin https://<sign-in host>` |
| `407` or `proxy authorization required` from older tools | Proxy authentication is on | Use `asm exec` or `eval "$(asm proxy-env)"` from a current CLI |

## 6. Remove

```bash
asm browser uninstall chrome [--profile NAME] [--user-data-dir DIR]
asm browser uninstall t3code
asm browser uninstall openbot [--restart]         # restarts OpenBot like the install
```

Uninstall restores what asm replaced, unless it changed since (then it says so and leaves
it). The last uninstall also removes the router service and its routes. Remove extra pieces
yourself: an OpenBot proxy or profile, the `openbot.service` drop-in, or a system router
unit.
