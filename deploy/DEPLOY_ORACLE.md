# Run Shield 24/7 on Oracle Cloud Always Free

Same result as `DEPLOY.md` (Azure), on Oracle's free-forever servers. Only **steps 1–3 differ**;
from step 4 on you follow `DEPLOY.md`, with one change in the Cloudflare step (marked below).

**Important Oracle rules (from Oracle's own docs):**
- A credit card and phone number are needed to sign up. Oracle says the card isn't charged unless you
  **upgrade** the account. Never click *Upgrade to paid*.
- You choose a **home region** once at sign-up; free servers can only be created there.
- Oracle may **reclaim "idle" free servers**: over 7 days, CPU (95th percentile), network **and** memory
  (ARM only) all below 20%. That's why we create a **small** server (1 CPU, 2 GB RAM): Shield's memory use
  is then around 20% or more, and the live radar keeps it busy. This lowers the risk; it isn't a guarantee.

---

## 1. Create the Oracle account

1. Go to **https://www.oracle.com/cloud/free/** → **Start for free**.
2. Country: United Arab Emirates. Fill in your name and email, then verify the email.
3. **Home region:** choose **UAE East (Dubai)** or **UAE Central (Abu Dhabi)** (closest to your users).
   You can't change it later.
4. Verify your phone, then add the card (verification only).
5. Wait for the "account is ready" email (minutes, sometimes longer), then sign in at **https://cloud.oracle.com**.

## 2. Create the server

Menu **☰** → **Compute** → **Instances** → **Create instance**.

| Setting | Value |
|---|---|
| Name | `shield-server` |
| Image | **Change image** → **Ubuntu** → **Canonical Ubuntu 24.04** |
| Shape | **Change shape** → **Ampere** → **VM.Standard.A1.Flex** → **1 OCPU**, **2 GB memory** (shows *Always Free-eligible*) |
| Networking | Keep the defaults (new virtual network); **Assign a public IPv4 address: Yes** |
| Add SSH keys | **Generate a key pair for me** → **Save private key** (and save the public key too) |
| Boot volume | Keep the default |

Click **Create**. When the instance is **Running**, copy its **Public IP address**.

**If you get "Out of capacity for shape VM.Standard.A1.Flex":** free ARM servers are often full. Try again
later (early morning often works), or use the always-available fallback: shape **VM.Standard.E2.1.Micro**
(AMD, 1 GB RAM, also *Always Free-eligible*). Shield runs on it too, thanks to the swap the setup script adds.

**Save the private key safely.** It's the only way into the server. Move it to:
`C:\Users\qamar\.ssh\shield-oracle.key` (create the `.ssh` folder if it doesn't exist).

## 3. Connect from your laptop (cmd)

Windows refuses keys that other users could read, so lock the file to your account first:

```
icacls C:\Users\qamar\.ssh\shield-oracle.key /inheritance:r
icacls C:\Users\qamar\.ssh\shield-oracle.key /grant:r "%USERNAME%":R
```

Then connect (the username on Oracle's Ubuntu servers is **ubuntu**):

```
ssh -i C:\Users\qamar\.ssh\shield-oracle.key ubuntu@YOUR_SERVER_IP
```

Type `yes` the first time. The prompt changes to `ubuntu@shield-server:~$`.

**Optional, recommended:** allow SSH only from your own address. Oracle console → **Networking** →
**Virtual cloud networks** → your network → **Security Lists** → **Default Security List** →
edit the ingress rule for port 22 → change source `0.0.0.0/0` to your IP followed by `/32`.
Shield itself needs **no open ports**: the Cloudflare Tunnel only connects outwards.

## 4–7. Continue with DEPLOY.md

Follow **`DEPLOY.md` steps 4 to 7** exactly (download code, `.env`, `bash deploy/setup_server.sh`,
Cloudflare Tunnel, test), with **one difference in step 6**:

> When Cloudflare asks for the operating system, choose **Debian** and **arm64** (for the A1 server).
> If you used the AMD fallback (E2.1.Micro), choose **64-bit** instead.

## Checking you're not "idle"

On the server:

```
free -h          # "used" memory should be roughly 20% of total or more
uptime           # load average above 0 means the radar is working
sudo systemctl status shield
```

## Staying free

- Only use shapes labelled **Always Free-eligible**. Never click **Upgrade**.
- The free allowance includes 200 GB of disk in total; one server with the default boot volume fits easily.
