# Run Shield on aidashield.tech from a Windows laptop (free)

| Address | Goes to | Who can open it |
|---|---|---|
| `https://aidashield.tech`, `https://www.aidashield.tech` | public site, `http://localhost:8001` | everyone |
| `https://app.aidashield.tech` | analyst dashboard, `http://localhost:8000` | only Team AIDA (Cloudflare Access email code) |

The site is online only while the laptop is **on, awake, connected**, the **tunnel service** is running
(starts with Windows) and **Shield** is running (`start_shield.bat`).

## 1. Tunnel (once)

1. Cloudflare → **Networking → Tunnels** → **Create a tunnel → Cloudflared** → name `shield-laptop` → **Windows, 64-bit**.
2. Copy the `cloudflared.exe service install ...` command and paste it into **Command Prompt as Administrator**.
   The token in that command is a password: never paste it in chats or screenshots.
   If it says *already installed*: run `cloudflared service uninstall` first, then the command again.
3. Check: `sc query Cloudflared` → `STATE : 4 RUNNING`; Cloudflare shows the connector **Healthy**.

## 2. Routes (once)

Tunnel → **Routes → Add route → Published application**:

| Subdomain | Domain | Service URL |
|---|---|---|
| *(empty)* | aidashield.tech | `http://localhost:8001` |
| `www` | aidashield.tech | `http://localhost:8001` |
| `app` | aidashield.tech | `http://localhost:8000` |

Use `http://` (not `https://`). If a DNS record already exists, delete it in **DNS → Records** and save the route again.

## 3. Protect the dashboard (once, required)

**Zero Trust → Access → Applications → Add an application → Self-hosted**:
name `Shield Admin`, public hostname `app` . `aidashield.tech`, policy **Team AIDA**
(Allow, Include → Emails → each teammate), login method **One-time PIN** → Save.

Test in a private window: `https://app.aidashield.tech` must ask for an email code first.

## 4. Start Shield

Double-click **`start_shield.bat`** (keep the window open; minimizing is fine). Expected:

```
Loading model: ok
Known phishing domains loaded: ...
Live radar started.
Shield running:
  dashboard  http://127.0.0.1:8000
  public     http://127.0.0.1:8001
```

`Loading model: MISSING` → run `python ml\train_baseline.py` once (with `.venv` activated).

Start automatically at login: **Windows + R** → `shell:startup` → put a **shortcut** to `start_shield.bat` in that folder.

## 5. Keep the laptop awake

- Settings → System → Power & battery → sleep when plugged in: **Never**.
- Control Panel → Power Options → *Choose what closing the lid does* → plugged in: **Do nothing**.

## Troubleshooting

| You see | Meaning | Fix |
|---|---|---|
| Error **1033** | tunnel not connected | admin cmd: `net start Cloudflared` |
| **502 Bad Gateway** | Shield not running | run `start_shield.bat` |
| `10048` / address in use | Shield already running in another window | close the other window |
| dashboard opens with no email code | Access app missing | step 3 |
