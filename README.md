# Wurzen Secure

Private invite-only encrypted messaging MVP with mobile-ready PWA support and a GitHub Actions Android APK builder.

## What is included

- Branded responsive mobile-first interface
- Invite-only registration
- Admin approval before users can login
- Private conversations between approved users
- Browser-side AES-GCM message encryption using a shared conversation passphrase
- Server stores ciphertext, IV and salt only
- Admin invite/user/audit area
- PWA manifest, service worker and icon
- Capacitor Android wrapper
- GitHub Actions workflow to build a debug APK

## Important security note

This is a strong MVP scaffold, not a finished Signal/WhatsApp replacement. Real production end-to-end encryption should use audited protocols such as Signal Protocol / MLS, formal key exchange, device identity verification, key rotation, backup policy, abuse controls and independent security review.

## Run locally

```bash
pip install -r requirements.txt
uvicorn app:app --reload --port 8000
```

Open:

```text
http://127.0.0.1:8000
```

Default first-run admin:

```text
username: admin
password: change-this-admin-password
```

Set a safer admin password before first run:

```bash
export PRIVMSG_ADMIN_PASSWORD="use-a-long-random-password"
```

## Phone/PWA access

Host the FastAPI app on a real HTTPS domain. Android users can open the site in Chrome and choose **Add to Home screen** / **Install app**.

## APK build with GitHub Actions

Upload the contents of this folder to the root of a GitHub repository. The repo should contain `.github`, `mobile`, `static`, `app.py`, `README.md`, and `requirements.txt` at the top level.

Then:

1. Open the repo on GitHub.
2. Go to **Actions**.
3. Select **Build Android APK**.
4. Tap **Run workflow**.
5. Download the APK from **Artifacts**.

Before building for a real hosted app, edit:

```text
mobile/capacitor.config.json
```

Replace:

```text
https://YOUR-DOMAIN-HERE
```

with your live HTTPS domain.

## APK output

GitHub artifact name:

```text
wurzen-secure-debug-apk
```
