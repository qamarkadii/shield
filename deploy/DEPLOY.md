# Run Shield 24/7 on a server

Result when finished:

| Address | Who | What |
|---|---|---|
| `https://aidashield.tech` (+ `www.`) | Anyone | Public "Is this link official?" page (Arabic/English) |
| `https://app.aidashield.tech` | Team only (Cloudflare Access login) | Analyst dashboard |

The server runs `run_shield.py` (both sites + live radar) as a service: it starts by itself
after a reboot and restarts within 5 seconds if it crashes. Both sites listen only on the
server itself (127.0.0.1); the only way in from the internet is the Cloudflare Tunnel.

**Memory needed:** about 340 MB to run, about 1 GB to train. A 1 GB server works because the
setup script adds 2 GB of swap.

---

## 0. Before you start (on your laptop)

Push the latest code so the server can download it:

```
cd C:\shield
git add -A
git commit -m "Public site and deployment"
git push
```

## 1. Get Azure for Students (free, no credit card)

1. Open https://azure.microsoft.com/free/students and click **Start free**.
2. Sign in and verify with your **university email**. You get **$100 credit for 12 months**, renewable yearly while you're a student.

If verification fails: a Hetzner Cloud CX22 server (about €4/month, 4 GB RAM) works with the same steps from step 3, using Ubuntu 24.04.

## 2. Create the server (Azure portal)

Go to https://portal.azure.com → **Virtual machines** → **Create** → **Azure virtual machine**.

| Setting | Value |
|---|---|
| Subscription | Azure for Students |
| Resource group | Create new: `shield` |
| Virtual machine name | `shield-server` |
| Region | **UAE North** if the size below is available there; otherwise **West Europe** |
| Image | **Ubuntu Server 24.04 LTS – x64 Gen2** |
| Size | **B2ats v2** or **B1s** (look for the *free services eligible* label) |
| Authentication type | **Password** — username `azureuser`, a long strong password (save it) |
| Public inbound ports | **Allow selected ports → SSH (22)** only |

Click **Review + create** → **Create**. When it's done, open the VM and copy its **Public IP address**.

**Lock down SSH:** VM → **Networking** → the rule for port 22 → change **Source** to **My IP address** → Save.
(If your IP changes and you're locked out, use **Run command** or **Serial console** in the portal.)

**Avoid surprise costs:** Azure portal → **Cost Management** → **Budgets** → create a budget of $10 with an email alert.

## 3. Connect to the server (from your laptop, cmd)

```
ssh azureuser@YOUR_SERVER_IP
```

Type `yes` the first time, then your password. The prompt changes to `azureuser@shield-server:~$`.
Everything from here to step 5 is typed **on the server**.

## 4. Download Shield onto the server

The repo is private, so GitHub needs a token:
GitHub → **Settings** → **Developer settings** → **Personal access tokens** → **Fine-grained tokens** →
**Generate new token** → Repository access: **Only select repositories → shield** →
Permissions: **Contents: Read-only** → Generate. Copy it.

```
git clone https://github.com/qamarkadii/shield.git
cd shield
```

Username: your GitHub username. Password: **paste the token** (it won't show while you paste; that's normal).

## 5. Add your email settings and run the setup

Create `.env` (same content as on your laptop, with your **new** App password):

```
nano .env
```

Paste, then save with **Ctrl+O**, **Enter**, and exit with **Ctrl+X**. Then:

```
bash deploy/setup_server.sh
```

It takes about 5–10 minutes. At the end you should see:

```
dashboard (8000): HTTP 200
public    (8001): HTTP 200
```

## 6. Connect the Cloudflare Tunnel to the server

In Cloudflare → **Networking** → **Tunnels**:

1. If you already created a tunnel for your laptop, open it; otherwise **Create Tunnel** (name `shield-server`).
2. Choose **Debian**, **64-bit**. Cloudflare shows install commands. Run them **on the server** (in the ssh window). The last one looks like `sudo cloudflared service install eyJ...` (the token is a password: don't share it).
3. Wait until the tunnel shows **Healthy**.
4. If the tunnel was also running on your laptop, stop it there so only the server answers (cmd as Administrator: `cloudflared service uninstall`).
5. **Routes** → **Add route** → **Published application**, three times:

| Subdomain | Domain | Service URL | Protect with Access |
|---|---|---|---|
| `app` | aidashield.tech | `http://localhost:8000` | **On** (Team AIDA policy) |
| *(empty)* | aidashield.tech | `http://localhost:8001` | Off |
| `www` | aidashield.tech | `http://localhost:8001` | Off |

## 7. Test

- On your phone (mobile data, not Wi-Fi): open **https://aidashield.tech** → check `sa1ik-fines.xyz` → it should say high risk.
- Open **https://app.aidashield.tech** → it should ask for your email and a code, then show the dashboard with the radar running.
- Turn your laptop off. Both should still work.

## Everyday commands (on the server)

```
sudo systemctl status shield          # is it running?
sudo journalctl -u shield -f          # live log (Ctrl+C to leave)
sudo systemctl restart shield         # restart
```

**Update to new code:**

```
cd ~/shield
git pull
.venv/bin/pip install -r requirements.txt
.venv/bin/python ml/train_baseline.py      # only if scoring or training code changed
sudo systemctl restart shield
```

The phishing feeds refresh automatically every night at 03:00 UAE time.

## Notes

- **Retraining from the dashboard** on a 1 GB server uses swap, so it's slower (a few minutes). Do it at quiet times.
- **The database** (`data/shield.db`) lives on the server; detections and labels from your laptop are not copied.
- **Credit:** one free-size VM running 24/7 fits the monthly free hours; the public IP and disk may use a little credit. Check Cost Management weekly.
