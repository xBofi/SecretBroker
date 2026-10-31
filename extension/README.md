# SecretBroker browser extension

Fills the logins saved in SecretBroker in Chrome, Edge, Brave and Firefox: a SecretBroker button in login and 2FA
fields with the logins saved for that site, a popup (search, fill, copy user / password / 2FA code, open the app),
the shortcut **Ctrl+Shift+L** (fill) and **Ctrl+Shift+Y** (open the popup), and "Save this login?" after a form is
sent. One Manifest V3 source for every browser.

How it works and why it is safe: [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md) section 1.3 and
[docs/THREAT_MODEL.md](../docs/THREAT_MODEL.md) section 3.8. In short:

- It talks to SecretBroker only through **native messaging** (`secretbroker/native_host.py`, started by the browser),
  never through a network port.
- SecretBroker decides which logins belong to a page (registrable domain, Public Suffix List), only answers this
  extension's ids, and only once the user connected the browser with one click in the app.
- Nothing is filled on page load: only after a click in our menu or popup, or the shortcut; never into a hidden field
  or a frame of another site.

## Files

| File | What |
|---|---|
| `manifest.json` | MV3 manifest. `key` pins the extension id (`cekklnambceaikefialdjijgolamnnab`) for unpacked installs; `browser_specific_settings.gecko.id` is Firefox's (`autofill@secretbroker`). Both must match `native_host.CHROME_EXTENSION_IDS` / `FIREFOX_EXTENSION_IDS`. |
| `background.js` | The only part that talks to the native host. Keeps per-tab state (frames with login forms, a pending "save?") in `storage.session`. |
| `content.js` | Finds login and 2FA fields, draws the button, menu, save bar and notices in a closed shadow root, fills after trusted events, notices submitted forms. |
| `popup.*` | The toolbar popup, styled like `secretbroker/web/styles.css` (Grafito, light and dark). |

## Installing it today (no terminal)

SecretBroker's installer copies this folder to `C:\Program Files\SecretBroker\extension` and registers the native
host for the user (HKCU keys for Chrome, Chromium, Edge, Brave and Firefox; the app does it again at every start).
In the app, **Ajustes › Navegador › Instalar la extensión** opens the browser's extensions page and the folder:

- Chrome / Edge / Brave: turn on *Developer mode*, *Load unpacked*, pick the folder. The pinned key keeps the id
  the native host allows.
- Firefox: `about:debugging` › *This Firefox* › *Load Temporary Add-on…* › `manifest.json`. Firefox removes temporary
  add-ons when it closes, and release Firefox only installs permanently what Mozilla signed: until it is on
  addons.mozilla.org it has to be loaded again after each restart. Firefox also asks separately for access to all
  sites (Manifest V3 host permissions are optional there): allow it from the extensions button, or the fields
  will not get the SecretBroker button.

Then open the extension and press **Conectar**: the app shows the same 6-digit code and connects it with one click.

On Linux and macOS, the packages (`.deb` `postinst`, `.pkg` `postinstall`) run `native_host.register()` as each
desktop account, and the app runs it again at every start: it writes a launcher and the host manifest into each
browser's per-user folder (`~/.config/...` on Linux, `~/Library/Application Support/...` on macOS).

## Publishing to the stores (needs the owner's developer accounts)

Publishing is what turns installing into one click (and is the only way Firefox keeps it permanently). Each store
needs an account in the owner's name, and each assigns the extension its own id:

| Store | Account | Notes |
|---|---|---|
| Chrome Web Store | Google developer account (one-time fee) | Upload a zip of this folder **without** `key`. The store gives the item an id; add it to `native_host.CHROME_EXTENSION_IDS` (or copy the store's public key into `key` so unpacked builds keep the same id). Brave installs from the Chrome Web Store. |
| Microsoft Edge Add-ons | Microsoft Partner Center (free) | Same zip; Edge assigns another id: add it to `CHROME_EXTENSION_IDS` too. |
| Firefox Add-ons (AMO) | addons.mozilla.org account (free) | Keeps `autofill@secretbroker`. Listed or self-distributed (signed `.xpi`), reviewed by Mozilla. |

Every store asks for a privacy policy (the extension sends page addresses to the local SecretBroker app only, never
to a server) and a justification of `nativeMessaging` and `<all_urls>` (needed to find login fields on any site).
Release the app with the new ids **before** the store build goes live, or the host will refuse the new extension.
