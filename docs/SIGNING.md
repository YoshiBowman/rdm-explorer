# Signing & Notarizing macOS Builds (via GitHub Actions)

The release workflow (`.github/workflows/build.yml`) signs and notarizes the macOS
builds automatically **when five GitHub secrets are present**. Until then it builds
unsigned. No certificates ever touch a local machine — everything happens on the
GitHub-hosted macOS runner.

Do this once. After that, every tag you push (`git tag v1.0.1 && git push origin v1.0.1`)
produces signed, notarized `.dmg`s plus the Windows and Linux installers, attached to a
draft release for you to review and publish.

---

## 1. Create a "Developer ID Application" certificate

This is the certificate for distributing apps **outside** the Mac App Store.

**Easiest (Xcode):** Xcode → Settings → Accounts → select your team → **Manage
Certificates…** → **+** → **Developer ID Application**. It's created and installed in
your login keychain.

**Without Xcode (web):**
1. Open **Keychain Access** → menu **Keychain Access → Certificate Assistant →
   Request a Certificate From a Certificate Authority…**
   - Enter your email, leave "CA Email" blank, choose **Saved to disk**. This makes a
     `CertificateSigningRequest.certSigningRequest` file.
2. Go to <https://developer.apple.com/account/resources/certificates/list> → **+** →
   **Developer ID Application** → upload the CSR → download the resulting `.cer`.
3. Double-click the `.cer` to install it into your login keychain.

## 2. Export it as a `.p12`

In **Keychain Access**, find **"Developer ID Application: Your Name (TEAMID)"** under
*login → My Certificates* (expand it so the private key is included). Right-click →
**Export…** → save as `DeveloperID.p12` and set an export password (you'll need it below).

## 3. Base64-encode the `.p12`

```bash
base64 -i DeveloperID.p12 | pbcopy      # copies the base64 blob to your clipboard
```

## 4. Create an app-specific password (for notarization)

<https://appleid.apple.com> → Sign-In and Security → **App-Specific Passwords** → **+** →
name it "rdm-explorer notarize". Copy the generated `xxxx-xxxx-xxxx-xxxx` password.

## 5. Find your Team ID

<https://developer.apple.com/account> → **Membership** → 10-character **Team ID**
(e.g. `A1B2C3D4E5`).

---

## 6. Add the five GitHub secrets

Repo → **Settings → Secrets and variables → Actions → New repository secret**. Add:

| Secret name | Value |
|-------------|-------|
| `MAC_CERT_P12_BASE64` | the base64 blob from step 3 |
| `MAC_CERT_PASSWORD` | the `.p12` export password from step 2 |
| `APPLE_ID` | your Apple ID email |
| `APPLE_APP_SPECIFIC_PASSWORD` | the app-specific password from step 4 |
| `APPLE_TEAM_ID` | your 10-character Team ID from step 5 |

## 7. Trigger a signed release

```bash
git tag v1.0.1
git push origin v1.0.1
```

Watch **Actions**. The macOS job logs `🔐 Signing + notarizing …`, uploads signed
`.dmg`s to a **draft** release; edit the notes and publish.

> To re-issue the **existing** v1.0.0 as signed instead of cutting a new version,
> delete and re-push the tag (`git push origin :v1.0.0 && git push origin v1.0.0`);
> the workflow will rebuild it signed. (You already have unsigned v1.0.0 assets, so a
> clean `v1.0.1` is usually simpler.)

## Verifying a signed build

```bash
codesign --verify --deep --strict --verbose=2 "/Applications/RDM Explorer.app"
spctl -a -vvv -t install "/Applications/RDM Explorer.app"   # should say: accepted, source=Notarized Developer ID
```
