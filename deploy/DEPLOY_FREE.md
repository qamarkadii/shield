# Run Shield 24/7 for free (no credit card)

| Piece | Free service | Job |
|---|---|---|
| Run Shield (Python, model, live radar) | **Hugging Face Spaces**, CPU Basic (2 vCPU, 16 GB RAM) | the server |
| `aidashield.tech` | **Cloudflare Worker** | forwards your domain to the Space |
| Stay awake | **cron-job.org** or **UptimeRobot** | visits the site every few minutes (free Spaces sleep after 48 h without visitors) |
| Keep the database | **Hugging Face private dataset** | automatic backup every 10 minutes, restored on restart |
| Alert emails | **Resend** (3,000/month, 100/day) | Spaces block normal email ports, Resend works over HTTPS |

Result:

- `https://aidashield.tech`: public "Is this link official?" page (anyone)
- `https://aidashield.tech/admin/`: analyst dashboard. The browser asks for a login: username **aida**, password = your `SHIELD_ADMIN_PASSWORD`.

---

## 1. Hugging Face account and token

1. Sign up at **https://huggingface.co/join** (free, no card).
2. **Settings → Access Tokens → Create new token** → type **Write** → name `shield` → copy it.
   It's a password: don't share it or put it in code.

## 2. Create the Space

**https://huggingface.co/new-space**:

| Field | Value |
|---|---|
| Space name | `shield` |
| SDK | **Docker** → **Blank** |
| Hardware | **CPU basic · FREE** |
| Visibility | **Public** (the public site must be reachable; the dashboard has its own password) |

## 3. Add the settings (before the first build)

Space → **Settings → Variables and secrets**:

| Type | Name | Value |
|---|---|---|
| Secret | `SHIELD_ADMIN_PASSWORD` | a long password for the dashboard |
| Variable | `SHIELD_RADAR` | `1` |
| Secret | `HF_TOKEN` | the Write token from step 1 |
| Variable | `SHIELD_BACKUP_REPO` | `YOUR-HF-USERNAME/shield-data` (created automatically, private) |
| Secret | `RESEND_API_KEY` | from step 7 (add later; until then alerts are saved, not emailed) |
| Variable | `ALERT_FROM` | `alerts@aidashield.tech` |
| Variable | `ALERT_TO` | `shield.2026.aida@gmail.com` |

## 4. Upload the code (laptop, cmd)

```
cd C:\shield
git add -A
git commit -m "Free deployment"
git remote add space https://huggingface.co/spaces/YOUR-HF-USERNAME/shield
git push --force space main
```

Username: your HF username. Password: **the Write token**.
`--force` is needed only this first time: it replaces the placeholder files the new Space started with.
(If it says the remote already exists, skip the `git remote add` line.)

The Space now **builds**: it installs everything and trains the model (about 5–10 minutes).
Watch the **Logs** tab. When it shows `Model: ok` and `Live radar started`, open the **App** tab.

Your Space's direct address is `https://YOUR-HF-USERNAME-shield.hf.space` (also shown under **⋮ → Embed this Space**).

## 5. Put it on aidashield.tech (Cloudflare Worker)

1. Cloudflare → **Workers & Pages → Create → Worker** → name `shield-proxy` → **Deploy**.
2. **Edit code** → replace everything with `deploy/cloudflare-worker.js` → **Deploy**.
3. **Settings → Variables and secrets → Add**: `SPACE_URL` = `https://YOUR-HF-USERNAME-shield.hf.space`.
4. **Settings → Domains & Routes → Add → Custom domain**: `aidashield.tech`, then again for `www.aidashield.tech`.
5. If you created tunnel routes earlier for these names, delete them first (Networking → Tunnels → your tunnel → Routes).

## 6. Keep it awake

Free Spaces sleep after 48 hours with no visitors. A free pinger prevents that:
**https://cron-job.org** (or UptimeRobot) → new job → URL `https://aidashield.tech/api/health` → every **5 minutes**.

## 7. Alert emails (Resend)

1. Sign up at **https://resend.com** → **Domains → Add domain** → `aidashield.tech`.
2. Resend shows DNS records. Add each one in **Cloudflare → DNS → Records**, then click **Verify** in Resend.
3. **API Keys → Create** (sending access) → copy it → add it as the `RESEND_API_KEY` secret (step 3).
4. Space → **Settings → Restart**. Test with the **Alert** button on the dashboard.

## 8. Test

- Phone on mobile data → `https://aidashield.tech` → check `sa1ik-fines.xyz` → **High risk**.
- `https://aidashield.tech/admin/` → login **aida** + your password → dashboard with the radar running.
- Turn your laptop off. Everything keeps working.

## Updating

```
cd C:\shield
git add -A
git commit -m "describe the change"
git push            # GitHub
git push space main # Hugging Face (rebuilds the Space automatically)
```

## Honest limits

- Free hardware with no uptime guarantee: Hugging Face can restart the Space (e.g. when you push, or for maintenance). After a restart the database comes back from the last backup (at most 10 minutes of changes lost).
- The Space address `*.hf.space` is also public. That's why the dashboard has its own password; Cloudflare Access alone would not protect it.
- The radar reads a live **sample** of the CT logs, the same as on a laptop.
