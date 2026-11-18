# Publishing the browser extension in the stores

Step by step, for someone who has never published an extension: the Chrome Web Store (also what Brave installs
from), Microsoft Edge Add-ons and addons.mozilla.org (AMO, Firefox). Every field has its text here, ready to paste.
The stores' rules below were read on 2026-11-18 ([sources](#sources)); the dashboards change their labels now and
then, so match a field by its meaning if its name differs a little.

What needs the owner: the three accounts (they are in your name), 5 USD for Google, and the clicks below. Everything
else is in the repository.

## The plan

| # | What | Who | Time |
|---|---|---|---|
| 1 | Build the zips and the images ([Before you start](#before-you-start)) | Claude, or one command each | 1 min |
| 2 | **Firefox**: create the account, upload, fill in, submit ([AMO](#firefox-add-ons-amo)). It needs nothing from the other steps: its id is already the one the app answers. | you | 15 min |
| 3 | **Chrome**: create the account, upload the zip as a draft, fill in everything, **do not submit yet** ([Chrome Web Store](#chrome-web-store)) | you | 20 min |
| 4 | **Edge**: create the account, upload the zip as a draft, fill in everything, **do not publish yet** ([Edge Add-ons](#microsoft-edge-add-ons)) | you | 20 min |
| 5 | Send back the two ids ([The ids the stores give back](#the-ids-the-stores-give-back)) | you | 1 min |
| 6 | Add the ids to the app (two lines) and release it | Claude | a release |
| 7 | Once that release is out: **Submit for review** in Chrome, **Publish** in Edge | you | 2 min |
| 8 | When each store approves it: send the three listing addresses, so the app and the README can link to them | you | 1 min |

Why the wait between 4 and 7: the app refuses any extension whose id it does not know, and a store's id only exists
after the first upload. A reviewer (or a user) who installs the store's extension with an older app sees
"SecretBroker is missing on this computer" although the app is there, and nothing works, so the app with the ids
must be downloadable first.

## Before you start

```
python tools/build_extension.py
python tools/store_images.py --screenshots
```

The first writes the two packages; the second the images, taking the screenshots from the newest run of
`tests/test_browser.py` on this PC (run that test first if there is none; it is run before every release anyway).

| File | For |
|---|---|
| `dist/secretbroker-extension-<version>-chromium.zip` | Chrome Web Store **and** Edge Add-ons (the same file) |
| `dist/secretbroker-extension-<version>-firefox.zip` | addons.mozilla.org |
| `extension/icons/128.png` | Chrome Web Store › Store icon |
| `dist/store/logo-300x300.png` | Edge Add-ons › Extension logo |
| `dist/store/promo-small-440x280.png` | Chrome Web Store and Edge Add-ons › small promotional tile |
| `dist/store/promo-marquee-1400x560.png` | Chrome Web Store › marquee, Edge Add-ons › large promotional tile (optional in both) |
| `dist/store/screenshot-1-popup.png` … `screenshot-5-app.png` | Screenshots, all three stores (1280x800) |

Never upload `extension/` itself or a zip made by hand: the stores do not take the `key` in its manifest, and each
store needs its own manifest (`tools/build_extension.py` explains what changes and why).

Have at hand:

- a **contact e-mail** you are happy to show in public (the stores display it as the developer's contact);
- a phone, for the two-step verification Google and Mozilla ask of developers;
- a card, for Google's 5 USD;
- the **privacy policy address**, which every store asks for:
  `https://github.com/xBofi/SecretBroker/blob/main/docs/PRIVACY.md`
  (it exists once this change is on `main`: open it in a browser before pasting it anywhere).

## The ids the stores give back

The app only talks to extensions whose id is in `secretbroker/native_host.py`. Nothing weakens that: a store's id is
added to the list, one line each.

| Store | Its id | Known in advance? |
|---|---|---|
| Firefox (AMO) | `autofill@secretbroker` | **Yes.** It is set by `browser_specific_settings.gecko.id` in the manifest, AMO keeps it, and the app already answers it. Nothing to send back. |
| Chrome Web Store | 32 letters (a to p), given at the first upload | **No.** Google makes a key pair for every new item and the id comes from it. The only documented way to make ids match goes the other way round (copying the store's public key into the unpacked manifest), which would change the id of the unpacked extension people already connected. Putting our own private key in the first upload is an undocumented trick with mixed reports; it is not used. |
| Edge Add-ons | 32 letters (a to p), given at the first upload, **different from Chrome's** | **No.** |

**What to send back after steps 3 and 4** (two strings, nothing else):

1. **Chrome Web Store › Item ID.** Right after uploading the zip you are on the item's page. The id is the 32
   letters in the address bar, `https://chrome.google.com/webstore/devconsole/<your publisher>/<ITEM ID>/edit`, and
   the dashboard also shows it as "Item ID".
2. **Edge Add-ons › CRX ID.** In Partner Center open the extension › **Extension overview** › section **Extension
   identity** and copy the **CRX ID** (32 letters). Not the "Product ID" (a long code with dashes) nor the "Store
   ID". If no CRX ID is shown before publishing, send a screenshot of that section.

Each goes in its marked line of `CHROME_EXTENSION_IDS` in `secretbroker/native_host.py`:

```python
CHROME_EXTENSION_IDS = (
    "cekklnambceaikefialdjijgolamnnab",  # unpacked, from the app's folder: pinned by "key" in extension/manifest.json
    "<the 32 letters>",                  # Chrome Web Store (Brave installs from it too)
    "<the 32 letters>",                  # Microsoft Edge Add-ons
)
```

`tests/test_extension_build.py` fails if a line is not 32 letters from a to p. The unpacked id stays first and keeps
working. Then release the app; only after that do step 7.

What users notice: the store's extension is a different extension from the unpacked one (in Chrome, Edge and
Brave), so it is connected once more from its window (one click and the code), and the unpacked one should be
removed from the browser's extensions page or two SecretBroker buttons appear. In Firefox it is the same extension:
the store's replaces the temporary one and stays after a restart.

Later, send the public addresses of the three listings: the app's **Settings › Browser › Install the extension**
still opens the folder to load it by hand, and should open the store's page instead once they exist (a change for a
later release).

## The texts

The same texts serve the three stores. English is the main language; Spanish goes in each store's Spanish listing.

### Name

```
SecretBroker
```

It comes from the package (`name` in the manifest); the stores show it as it is.

### Short description (Chrome: "Summary", Edge: "Short description")

Read from the package in each of its 32 languages (`ext_description` in `extension/_locales/`): there is nothing to
paste and it cannot be edited in Chrome's or Edge's dashboards. The limit is 132 characters; the longest of ours has
123, and the build refuses to make a zip if one goes over.

- English: `Fills in the passwords you keep in SecretBroker, only on their own website and only when you ask.`
- Spanish: `Rellena tus contraseñas guardadas en SecretBroker, solo en su web y solo cuando tú lo pides.`

### Summary (AMO only, at most 250 characters)

English:

```
Fills in the logins and 2FA codes you keep in the SecretBroker desktop app, only on the website each one belongs to and only when you ask. Needs the free, open source SecretBroker app installed on this computer.
```

Spanish:

```
Rellena los inicios de sesión y códigos 2FA que guardas en la app de escritorio SecretBroker, solo en la web de cada uno y solo cuando tú lo pides. Necesita la app SecretBroker, gratuita y de código abierto, instalada en este ordenador.
```

### Detailed description, English

(Edge asks for 250 to 10,000 characters; this has about 2,600, and the Spanish one about 2,800.)

```
SecretBroker for your browser fills in the logins and two-factor codes you keep in the SecretBroker desktop app. It needs the app installed on the same computer: the extension has no vault or account of its own.

IMPORTANT: this extension does nothing without the SecretBroker app (free and open source, for Windows, Ubuntu and macOS). Get it at https://github.com/xBofi/SecretBroker/releases/latest, then open the extension and click Connect.

WHAT IT DOES
• A SecretBroker button appears in login and 2FA code fields. Click it to see the logins saved for that website and fill one in.
• The toolbar window lists the logins for the website you are on: fill in, or copy the username, the password or the current 2FA code. Search the rest of your vault to open their websites.
• Alt+Shift+L fills in the login for the website without opening anything. You can change the shortcut.
• After you sign in somewhere new, it offers to save the login, or to update a password you changed. Nothing is stored until you click Save.
• Light and dark, in 32 languages.

BUILT TO BE HARD TO TRICK
• A login is only offered on the website it was saved for. The app decides, by registrable domain (Public Suffix List): lookalike addresses, other people's pages on shared hosts such as github.io and copies without HTTPS of an HTTPS website get nothing, not even the name of the login.
• Nothing is filled in when a page loads: only after your click or the shortcut, only in fields you can see, never in a frame from another website.
• The page cannot drive the extension's menu or fake your click.
• Every fill, copy and save shows up in the app's Activity.
• Team credentials shared as "use only" are never filled in, because that would show them to the page.

PRIVATE BY DESIGN
• The extension talks only to the SecretBroker app on your computer, through the browser's native messaging. No server, no network port, no account, no analytics.
• Your logins go from the app to the page you fill in, and nowhere else. The only thing the extension asks the internet for is each website's own icon, without cookies.
• You connect each browser once: the app shows a 6-digit code, you check that it matches and click Connect. You can disconnect it from the app at any time.

WHY IT ASKS FOR ACCESS TO ALL WEBSITES
A password manager has to find the login form on whatever website you sign in to. The extension looks only for username, password and code fields; it does not read or collect anything else from the pages you visit.

Open source (MIT): https://github.com/xBofi/SecretBroker
Privacy policy: https://github.com/xBofi/SecretBroker/blob/main/docs/PRIVACY.md
```

### Detailed description, Spanish

```
SecretBroker para tu navegador rellena los inicios de sesión y los códigos de dos pasos que guardas en la app de escritorio SecretBroker. Necesita la app instalada en el mismo ordenador: la extensión no tiene bóveda ni cuenta propias.

IMPORTANTE: esta extensión no hace nada sin la app SecretBroker (gratuita y de código abierto, para Windows, Ubuntu y macOS). Descárgala en https://github.com/xBofi/SecretBroker/releases/latest, abre la extensión y pulsa Conectar.

QUÉ HACE
• En los campos de inicio de sesión y de código 2FA aparece un botón de SecretBroker. Púlsalo para ver los inicios de sesión guardados para esa web y rellenar uno.
• La ventana de la barra del navegador muestra los inicios de sesión de la web en la que estás: rellena, o copia el usuario, la contraseña o el código 2FA del momento. Busca en el resto de tu bóveda para abrir sus webs.
• Alt+Mayús+L rellena el inicio de sesión de la web sin abrir nada. Puedes cambiar el atajo.
• Cuando entras en una web nueva, te ofrece guardar el inicio de sesión, o actualizar una contraseña que has cambiado. No se guarda nada hasta que pulsas Guardar.
• Claro y oscuro, en 32 idiomas.

HECHA PARA QUE NO LA ENGAÑEN
• Un inicio de sesión solo se ofrece en la web para la que se guardó. Lo decide la app, por dominio registrable (Public Suffix List): las direcciones parecidas, las páginas de otras personas en alojamientos compartidos como github.io y las copias sin HTTPS de una web con HTTPS no reciben nada, ni siquiera el nombre.
• No se rellena nada al cargar la página: solo tras tu clic o el atajo, solo en campos que puedes ver y nunca en un marco de otra web.
• La página no puede manejar el menú de la extensión ni fingir tu clic.
• Cada vez que se rellena, se copia o se guarda algo, queda en Actividad, en la app.
• Las credenciales de equipo compartidas como «solo uso» nunca se rellenan, porque eso se las mostraría a la página.

PRIVADA POR DISEÑO
• La extensión solo habla con la app SecretBroker de tu ordenador, por la mensajería nativa del navegador. Sin servidor, sin puerto de red, sin cuenta y sin analíticas.
• Tus inicios de sesión van de la app a la página que rellenas, y a ningún otro sitio. Lo único que la extensión pide a internet es el icono de cada web, sin cookies.
• Conectas cada navegador una vez: la app muestra un código de 6 cifras, compruebas que coincide y pulsas Conectar. Puedes desconectarlo desde la app cuando quieras.

POR QUÉ PIDE ACCESO A TODAS LAS WEBS
Un gestor de contraseñas tiene que encontrar el formulario de inicio de sesión en cualquier web en la que entres. La extensión solo busca campos de usuario, contraseña y código; no lee ni recoge nada más de las páginas que visitas.

Código abierto (MIT): https://github.com/xBofi/SecretBroker
Política de privacidad: https://github.com/xBofi/SecretBroker/blob/main/docs/PRIVACY.md
```

### Category

| Store | Choose |
|---|---|
| Chrome Web Store | **Privacy & Security** (Google's own description of it names "password safes") |
| Edge Add-ons | **Productivity** (where Edge lists password managers; its list has no security category that we know of. If yours shows one for privacy or security, take that) |
| AMO | **Privacy & Security** |

### Search terms (Edge only: at most 7 terms, 30 characters each, 21 words in all)

English: `password manager` · `autofill passwords` · `two-factor codes` · `TOTP` · `open source` · `secrets manager` ·
`SecretBroker`

Spanish: `gestor de contraseñas` · `autorrellenar contraseñas` · `códigos 2FA` · `TOTP` · `código abierto` ·
`gestor de secretos` · `SecretBroker`

### Addresses

| Field | Value |
|---|---|
| Homepage / Website | `https://github.com/xBofi/SecretBroker` |
| Support URL / Support website | `https://github.com/xBofi/SecretBroker/issues` |
| Privacy policy URL | `https://github.com/xBofi/SecretBroker/blob/main/docs/PRIVACY.md` |
| Support e-mail (AMO; Edge accepts an address instead of the support URL) | your contact e-mail |

### Single purpose (Chrome and Edge, "Single purpose description")

```
SecretBroker fills in, on the websites they belong to, the logins and two-factor codes the user keeps in the SecretBroker desktop app on the same computer, and offers to save the logins the user types.
```

### Why each permission (Chrome and Edge, "Permission justification"; one box per permission)

**nativeMessaging**

```
The extension has no vault, server or account of its own. Every login comes from, and is saved to, the SecretBroker desktop app installed on the same computer, which the extension reaches through native messaging (host "com.secretbroker.autofill"). It is the only channel on which the extension exchanges user data, and no network port is opened. The app answers only this extension's id, and only after the user connected this browser by confirming a code in the app.
```

**storage**

```
storage.local keeps (1) the random key that identifies this browser to the user's SecretBroker app, created when the user connects the browser, and (2) a small cache of website icons shown next to the logins. storage.session keeps, in memory and until the tab or the browser closes, which frames of a tab have a login form and a login waiting for the user's "Save / Not now" answer. The extension never writes a password to disk.
```

**activeTab**

```
When the user clicks the toolbar button or presses the fill shortcut, the extension needs the address of the current tab to ask the SecretBroker app which saved logins belong to that website. activeTab gives it that for the tab the user acted on, also when the user has limited the extension's site access to "on click" (or, in Firefox, has not granted it access to all websites).
```

**Host permission (`<all_urls>`)**

```
A password manager must work on whichever website the user signs in to, and that list cannot be known in advance. Host access is used for three things only: (1) reading the address of the active tab, so that the app can match saved logins by registrable domain (the anti-phishing check); (2) running the content script that finds login fields; (3) downloading a website's own icon (the tab's favicon, or /favicon.ico) to show next to its logins, without cookies or referrer. No page content is collected, and nothing is sent to any server: the extension only talks to the SecretBroker app on the same computer.
```

**Content script on every http and https page, in all frames** (there is no box of its own for it in Chrome or
Edge: it belongs to the host permission; this text is for a reviewer who asks, and for AMO's notes)

```
The content script finds username, password and one-time-code fields; shows the SecretBroker button inside the focused field; fills in the login the user picked, only after a trusted click or the keyboard shortcut and only into visible fields; and notices that a login form was sent, to offer to save it. It runs in all frames because sign-in forms are often inside an iframe of the same website; a frame from another website is never filled in. What it draws lives in a closed shadow root that the page's scripts cannot reach. It reads nothing of the page but those fields.
```

### Remote code (Chrome and Edge, "Are you using remote code?")

Choose **No, I am not using remote code**. No justification box appears. (True: `background.js`, `content.js` and
`popup.js` are the whole program; there is no `eval`, no script from the network and no WebAssembly, and
`tests/test_extension_build.py` checks the first two on every build.)

### Data usage (Chrome and Edge, "Data usage")

Google counts data as "handled" even when it never leaves the computer, so the truthful answer is not "nothing".

"What user data do you plan to collect from users now or in the future?"

| Box | Tick? | Why (from `extension/*.js`) |
|---|---|---|
| Personally identifiable information | no | The usernames of the logins are credentials: they are covered by the next box. |
| Health information | no | |
| Financial and payment information | no | |
| **Authentication information** | **yes** | It receives a login's username, password or 2FA code from the app to type it into the page, and reads the username and password the user typed in a login form to offer to save them. |
| Personal communications | no | |
| Location | no | |
| **Web history** | **yes** | It sends the address of the current page to the SecretBroker app on the same computer (when the user opens the extension, clicks its button, uses the shortcut or sends a login form), and the app's own activity log records the website where a login was filled in or saved. Never to a server. |
| User activity | no | It listens for typing only in login fields (that is the box above) and keeps no record of clicks, scrolling or keystrokes. |
| Website content | no | It looks for login fields and keeps the website's icon; it collects no text, images or links of the pages. |

"I certify that the following disclosures are true" - tick the three; all are true:

- I do not sell or transfer user data to third parties, outside of the approved use cases.
- I do not use or transfer user data for purposes that are unrelated to my item's single purpose.
- I do not use or transfer user data to determine creditworthiness or for lending purposes.

Firefox asks the same question in the manifest instead of in a form, and the build already answers it:
`data_collection_permissions.required = ["authenticationInfo", "browsingActivity"]`, because Mozilla's policies
count what an extension hands to a native application as data it transmits. Firefox shows those two when the
extension is installed.

### Notes for the reviewer

For Chrome (**Test instructions** › additional instructions; leave the username and password boxes empty), Edge
(**Notes for certification**) and AMO (**Notes for Reviewers**). Replace `<VERSION>` first: for AMO it is `0.19.0`;
for Chrome and Edge it is the version of the app released in step 6. The text is kept under 2,000 characters in
case a box is short; if one still cuts it, drop the "For the review" lines (the privacy fields say the same).

```
This is the browser side of SecretBroker, an open source (MIT) desktop password manager: https://github.com/xBofi/SecretBroker
It only works with the SecretBroker app installed on the same computer (native messaging, host "com.secretbroker.autofill"). Without the app its window says "SecretBroker is missing on this computer": that is expected.

To test (5 minutes, no account needed):
1. Install the app, version <VERSION> or newer: https://github.com/xBofi/SecretBroker/releases/latest (Windows .exe, Ubuntu .deb, macOS .pkg). The Windows installer is not code-signed yet: on the SmartScreen warning click "More info", then "Run anyway".
2. Open SecretBroker and create a vault (a master password of 12+ characters).
3. Click "Add a credential", choose "Website or service", enter the address of any page with a login form, a username and a password (made up is fine).
4. Click the extension's toolbar button, then "Connect". The app shows the same 6-digit code: click "Connect" there.
5. On that page click in the username or password field, then the SecretBroker button inside it, and choose the login: both fields are filled in.
6. Send a login form with another username and password: a bar offers to save it. Nothing is stored unless you click "Save".

For the review:
- No remote code: background.js, content.js and popup.js are the whole program, not minified, as in the repository's extension/ folder.
- User data goes only to the app on the same computer. The one network request is a fetch() of a website's own icon (favicon), without credentials or referrer, kept as a data: URL.
- All-sites access: the content script only looks for login and one-time-code fields, and fills in after a trusted click or the shortcut.
- innerHTML is assigned three times, always a constant from the same file (a stylesheet and two SVG icons).
- Privacy policy: https://github.com/xBofi/SecretBroker/blob/main/docs/PRIVACY.md
```

### Privacy policy text (AMO only: it wants the text itself, not only a link)

```
SecretBroker's browser extension fills in the logins and two-factor codes you keep in the SecretBroker app and offers to save the ones you type. It works only with that app, installed on the same computer.

What it reads: the address of the tab you are on, when you open the extension, click its button in a field, press the fill shortcut or send a login form; the username, password and one-time-code fields of the page; and the username and password you typed in a login form you send. Nothing else of the pages you visit is read, kept or sent.

Where it goes: only to the SecretBroker app on the same computer, through the browser's native messaging (no network port, no server). The app uses the page's address to decide which of your logins belong to that website, and stores a login you typed only if you click "Save" or "Update". Nothing is sent to the SecretBroker project, its developers or any third party. There are no analytics and no code is loaded from the internet.

What it keeps in the browser: a random key that identifies this browser to your app, and a small cache of website icons. In memory only, until the tab or the browser closes: which frames have a login form and a login waiting for your "Save?" answer. Removing the extension deletes all of it.

The one request it makes to the internet: a website's own icon (the tab's icon or /favicon.ico), fetched from that website without cookies and without saying which page asked, to show it next to that website's logins.

The full policy, including the desktop app and the team server: https://github.com/xBofi/SecretBroker/blob/main/docs/PRIVACY.md
```

## Chrome Web Store

**The account (once)**

1. Decide which Google account will own the extension. Google says its e-mail cannot be changed afterwards and
   recommends one used only for publishing. Turn on **2-Step Verification** for it
   (<https://myaccount.google.com/security>): Google requires it of every developer account before publishing.
2. Open <https://chrome.google.com/webstore/devconsole>, sign in, accept the developer agreement and pay the
   **one-time 5 USD registration fee**.
3. Left menu › **Account**. Fill in:
   - **Publisher name**: `SecretBroker` (shown as "Offered by").
   - **Contact e-mail**: type it and click **Verify e-mail**; open the message Google sends and click its link.
     Required for a new account.
   - **Trader / non-trader declaration** (asked of every developer for the European Union): only you can answer
     it. "Trader" means you publish as part of a business or profession; Google then verifies and **publicly
     shows** your legal name, address and phone number under the listing. "Non-trader" is for publishing outside
     any business. If SecretBroker is or will be sold as a product, ask whoever advises you on legal matters.
   - A physical address is only asked of extensions that sell something. Skip it.

**The item**

4. Left menu › **Items** › **Add new item** › **Choose file** ›
   `dist/secretbroker-extension-<version>-chromium.zip` › **Upload**. If it answers that the package or the
   manifest is not valid, stop and send the message as it is.
5. You are now on the item's page. **Copy the Item ID** (see [the ids](#the-ids-the-stores-give-back)).
6. Tab **Store listing**:
   - **Description**: paste [the English description](#detailed-description-english).
   - **Category**: Privacy & Security.
   - **Language**: English.
   - **Store icon**: `extension/icons/128.png`.
   - **Screenshots**: the five `dist/store/screenshot-*.png`, in their order (at least 1, at most 5; 1280x800).
   - **Small promo tile**: `dist/store/promo-small-440x280.png`. **Marquee promo tile**:
     `dist/store/promo-marquee-1400x560.png` (optional).
   - **Official URL**: leave "None". **Homepage URL** and **Support URL**: from [Addresses](#addresses).
   - **Mature content**: off.
   - At the top of the tab, change the language to **Spanish** and paste
     [the Spanish description](#detailed-description-spanish). The title and the summary are already there in
     every language: they come from the package.
7. Tab **Privacy practices**:
   - **Single purpose description**: [paste](#single-purpose-chrome-and-edge-single-purpose-description).
   - **Permission justification**: one box each for nativeMessaging, storage, activeTab and the host permission:
     [paste each](#why-each-permission-chrome-and-edge-permission-justification-one-box-per-permission).
   - **Are you using remote code?** No, I am not using remote code.
   - **Data usage**: tick **Authentication information** and **Web history**, and the three certifications
     ([why](#data-usage-chrome-and-edge-data-usage)).
   - **Privacy policy URL**: from [Addresses](#addresses).
8. Tab **Distribution**: Free of charge; Visibility **Public**; all regions.
9. Tab **Test instructions**: leave username and password empty; paste [the notes](#notes-for-the-reviewer) in the
   additional instructions, with `<VERSION>` replaced.
10. **Save draft**. Do **not** press "Submit for review" yet: send the Item ID (step 5 of the plan) and wait for
    the app's release.
11. After the release: open the item › **Submit for review** › confirm (leave "publish automatically after it has
    passed review" ticked). Google gives no fixed time; an extension that asks for every website gets a slower,
    deeper review. The answer comes by e-mail.

The dashboard may say that the item "requests broad host permissions" and that the review may take longer. That is
expected and is not an error.

## Microsoft Edge Add-ons

**The account (once)**. Free: Microsoft charges no registration fee.

1. Open <https://partner.microsoft.com/dashboard/microsoftedge/public/login> and sign in with a personal
   **Microsoft account** (outlook.com, hotmail.com, live.com; a work or school account is not accepted; you can
   also sign in with your GitHub account and one is made for you).
2. The **Microsoft Edge Developer Account Registration** form:
   - **Account country/region**: yours. It cannot be changed later.
   - **Account type**: **Individual** or **Company**. It cannot be changed later. Individual is verified quickly
     (only that the name is free); Company means days or weeks of checks of the registered business and a phone
     call to an "approver" you name. Choose Company only if a company must appear as the publisher.
   - **Publisher display name**: `SecretBroker` (50 characters at most; it must be free).
   - **Contact info**: yours. Microsoft uses it to write to you about the account.
   - Tick **I accept the terms and conditions** › **Finish**. Wait for the confirmation e-mail.

**The extension**

3. **Overview** › **Create new extension** › drag `dist/secretbroker-extension-<version>-chromium.zip` (the same
   file as for Chrome) onto the page. When it shows the package as verified, click **Continue**. A validation
   error: stop and send the message.
4. Left menu › **Extension overview** › **Extension identity**: **copy the CRX ID** (see
   [the ids](#the-ids-the-stores-give-back)).
5. **Availability**: Visibility **Public**; Markets: all (the default) › **Save & Continue**.
6. **Properties**: Category **Productivity**; **Website** and **Support contact detail** from
   [Addresses](#addresses); Mature content unticked › **Save & Continue**.
7. **Privacy**: the same answers as Chrome, in the same order: **Single Purpose Description**, a **Permission
   justification** per permission, **No, I am not using remote code**, **Data usage** (Authentication information
   and Web history, or the two boxes that mean the same if they are worded differently; the certifications) and
   the **Privacy Policy URL** › **Save & Continue**.
8. **Store listings**. There is one row per language found in the package. For **English** click **Edit details**:
   - **Description**: [the English description](#detailed-description-english).
   - **Extension logo**: `dist/store/logo-300x300.png`, then click **Duplicate this logo for all languages**.
   - **Small promotional tile**: `dist/store/promo-small-440x280.png`. **Large promotional tile**:
     `dist/store/promo-marquee-1400x560.png`.
   - **Screenshots**: the five `dist/store/screenshot-*.png` (6 at most), then **Duplicate**.
   - **Search terms**: [the English ones](#search-terms-edge-only-at-most-7-terms-30-characters-each-21-words-in-all).
   - "Extension name" and "Short description" cannot be edited: they come from the package.

   For **Spanish**: the Spanish description and search terms. Edge wants a description and a logo for every row
   that stays, so for each other language click **Remove** on its row: that only removes the store page's text
   in that language (it is then shown in English); the extension itself stays translated. If a row cannot be
   removed, paste the English description into it.
9. **Save draft**. Do **not** press "Publish" yet: send the CRX ID and wait for the app's release.
10. After the release: **Store listings** › **Publish** › paste [the notes](#notes-for-the-reviewer) in **Notes for
    certification** (with `<VERSION>` replaced) › **Publish**. Certification takes up to seven business days; the
    extension then shows as "In the Store".

Edge's own rule to keep in mind: the word "Chrome" must not appear in the name or the description. Ours do not use
it.

## Firefox Add-ons (AMO)

This one can be submitted today: the id is fixed and the released app already answers it.

**The account (once)**. Free.

1. Open <https://addons.mozilla.org/developers/> › **Register or Log in** with a Mozilla account (create one with
   your contact e-mail if you have none).
2. Turn on **two-step authentication** for that account (<https://accounts.firefox.com/settings> › Security):
   Mozilla asks it of everyone who signs in to AMO as a developer. Keep the recovery codes: losing them can lock
   you out of the add-on for good.
3. Back in the Developer Hub, accept the **Firefox Add-on Distribution Agreement** when it is shown.

**The add-on**

4. **Submit a New Add-on** (or "Submit Your First Add-on") › **On this site** › **Continue**.
5. **Select a file…** › `dist/secretbroker-extension-<version>-firefox.zip`. Wait for the validation:
   - warnings about "Unsafe assignment to innerHTML" are expected (three constants; the notes explain them) and do
     not stop you;
   - an **error** does: stop and send its text.
6. Compatible platforms: tick **Firefox** only, **not** Firefox for Android (it cannot talk to a desktop app) ›
   **Continue**.
7. "Do you need to submit source code?" **No**: nothing in the package is minified, bundled or generated; it is the
   repository's `extension/` folder. **Continue**.
8. **Describe Add-on**:
   - **Name**: `SecretBroker`. **Add-on URL**: `secretbroker` (if taken, `secretbroker-autofill`).
   - **Summary**: [the English summary](#summary-amo-only-at-most-250-characters).
   - **Description**: [the English description](#detailed-description-english).
   - **This add-on is experimental**: no.
   - **This add-on requires payment, non-free services or software, or additional hardware**: no. The app it needs
     is free and open source, and the description says it is needed.
   - **Categories**: Privacy & Security.
   - **Support e-mail**: your contact e-mail. **Support website**: from [Addresses](#addresses).
   - **License**: MIT License.
   - **This add-on has a privacy policy**: tick it and paste
     [the privacy policy text](#privacy-policy-text-amo-only-it-wants-the-text-itself-not-only-a-link).
   - **Notes for Reviewers**: [the notes](#notes-for-the-reviewer), with `<VERSION>` replaced by `0.19.0`.
9. **Submit Version**. Mozilla confirms by e-mail and writes again when it is reviewed.
10. Then, on the add-on's page in the Developer Hub (**Edit Product Page**): under **Images** add the five
    screenshots; with the language selector add **Español** and paste the Spanish summary and description.

When Firefox installs it, it shows that the extension handles "authentication information" and "browsing
activity". That is the declaration described under [Data usage](#data-usage-chrome-and-edge-data-usage): the app
on the same computer is the only recipient, and the listing and the privacy policy say so.

## Images

| Store | Image | Size the store asks for | File |
|---|---|---|---|
| Chrome | Store icon | 128x128 PNG | `extension/icons/128.png` |
| Chrome | Screenshots, 1 to 5 (one is required) | 1280x800 or 640x400 | `dist/store/screenshot-1` … `-5` |
| Chrome | Small promo tile (optional; without it the listing is shown after those that have one) | 440x280 | `dist/store/promo-small-440x280.png` |
| Chrome | Marquee promo tile (optional) | 1400x560 | `dist/store/promo-marquee-1400x560.png` |
| Edge | Extension logo (required, per language) | 1:1, 300x300 recommended, 128x128 at least | `dist/store/logo-300x300.png` |
| Edge | Small promotional tile (optional) | 440x280 | `dist/store/promo-small-440x280.png` |
| Edge | Large promotional tile (optional) | 1400x560 | `dist/store/promo-marquee-1400x560.png` |
| Edge | Screenshots, up to 6 (optional) | 1280x800 or 640x480 | `dist/store/screenshot-1` … `-5` |
| AMO | Icon | taken from the package | nothing to upload |
| AMO | Screenshots (optional) | 1280x800 recommended (1.6:1) | `dist/store/screenshot-1` … `-5` |

The screenshots come from `tests/test_browser.py`, which saves them at the size of the browser window (1256x808) or
of the popup (360 wide), sizes no store takes. `tools/store_images.py --screenshots` fits these five to 1280x800:

| Store screenshot | From the test's | Shows |
|---|---|---|
| `screenshot-1-popup.png` | `…-05-popup-logins-light.png` | The toolbar window with the website's logins: fill, copy, search |
| `screenshot-2-menu.png` | `…-08-menu-light.png` | The button in the field and the menu of logins |
| `screenshot-3-2fa.png` | `…-10-menu-2fa.png` | Filling in a 2FA code |
| `screenshot-4-save.png` | `…-15-save-bar-light.png` | "Save this password in SecretBroker?" |
| `screenshot-5-app.png` | `…-04-app-settings-browser.png` | The app's Settings › Browser with the browser connected |

They are honest but plain: the test's pages are bare forms on `shop.localhost`, shown at twice their size. They are
enough to pass a review. A set made on a page that looks like a real website, captured at double resolution, would
sell the extension better; that needs a change to `tests/test_browser.py` and is not done.

The promotional images have no text on purpose: the stores show the same image in every language.

## Updating it later

The extension's version is the app's (`extension/manifest.json` and `pyproject.toml` are bumped together; the test
checks it), and a store only takes a version higher than the last one it has. After a release that changed
`extension/`:

1. `python tools/build_extension.py`
2. Chrome: the item › **Package** › **Upload new package** › **Submit for review**.
3. Edge: the extension › **Packages** › replace the package › **Publish**.
4. AMO: the add-on › **Upload New Version**.

Each update is reviewed again. A release that does not touch `extension/` needs no upload: the stores keep the
version they have, and the app keeps answering it.

## What a reviewer may question

Checked for this guide; none of it stops an upload.

| Point | Where it stands |
|---|---|
| Remote code, `eval` | None. Checked on every build by `tests/test_extension_build.py`. |
| Access to every website (`<all_urls>`, a content script on every page) | Needed and justified above. It makes the review slower. The code only acts on http and https pages, so the host permission could be narrowed to `http://*/*` and `https://*/*`; that changes the unpacked extension too and needs a run of `tests/test_browser.py`, so it is left for a later change. |
| `activeTab` next to `<all_urls>` | Not redundant: it is what works when the user limits the extension to "on click", and in Firefox when access to all websites is not granted. Justified above. |
| It needs a program outside the store | The description says so at the top, and the notes tell the reviewer how to install and test it. If a reviewer cannot run the unsigned Windows installer, offer the `.deb` or a short screen recording (Chrome and Edge have a field for a YouTube link). |
| `innerHTML` (AMO's validator warns three times) | Constants only; explained in the notes. |
| Description and name limits, `_locales` | 32 languages, all with the description (123 characters at most, limit 132). Two messages in `_locales` are no longer used (`it_only_fills_in_on`, `nothing_saved_for`): harmless. |
| Icons | 16, 32, 48 and 128 are in the package. Google suggests that the 128 icon keep its artwork within 96x96 with a transparent margin; ours fills about 118. It is a guideline, not checked at upload. |
| Asking the user's consent inside the extension | Chrome asks for an in-product disclosure only for data handling that is not part of the purpose shown in the listing. Filling in and saving logins is the purpose. Firefox shows its own consent when installing (the manifest declares the data). |
| Chrome's "Limited Use" statement | It must be on the extension's website or in its privacy policy: it is in `docs/PRIVACY.md`, under the extension. |

## Sources

Read on 2026-11-18.

**Chrome Web Store**

- Registering, the one-time fee, the e-mail that cannot be changed: <https://developer.chrome.com/docs/webstore/register>;
  the amount (5 USD): <https://support.google.com/chrome/a/answer/2714278>
- Account page (publisher name, verified e-mail): <https://developer.chrome.com/docs/webstore/set-up-account>
- 2-Step Verification required of developers: <https://developer.chrome.com/docs/webstore/program-policies/policies>
- Trader declaration: <https://developer.chrome.com/docs/webstore/program-policies/trader-verification-faq>
- Uploading, the tabs, deferred publishing: <https://developer.chrome.com/docs/webstore/publish>
- Listing fields and images: <https://developer.chrome.com/docs/webstore/cws-dashboard-listing>,
  <https://developer.chrome.com/docs/webstore/images>
- Categories: <https://developer.chrome.com/docs/webstore/best-practices>
- Privacy practices tab: <https://developer.chrome.com/docs/webstore/cws-dashboard-privacy>
- What counts as handling user data (also when it stays on the device; a native program on the same computer):
  <https://developer.chrome.com/docs/webstore/program-policies/user-data-faq>,
  <https://developer.chrome.com/docs/webstore/program-policies/limited-use>
- Manifest limits (name 75, short name 12, description 132): <https://developer.chrome.com/docs/extensions/reference/manifest>
- The `key` field and where the store's id comes from: <https://developer.chrome.com/docs/extensions/reference/manifest/key>;
  developers' reports that a new item with `key` is refused, and on the `key.pem` trick:
  <https://groups.google.com/a/chromium.org/g/chromium-extensions/c/x_NBS6_-NKs>,
  <https://groups.google.com/a/chromium.org/g/chromium-extensions/c/Su50pbNzRms>
- `background.scripts` in Manifest V3 (refused before Chrome 121, ignored from 121), `service_worker` in Firefox:
  <https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/background>

**Microsoft Edge Add-ons**

- Registering (free, individual or company): <https://learn.microsoft.com/en-us/microsoft-edge/extensions/publish/create-dev-account>
- Publishing, every page of Partner Center, the listing's limits, seven business days:
  <https://learn.microsoft.com/en-us/microsoft-edge/extensions/publish/publish-extension>
- Porting from Chrome ("Chrome" in the name or description, `update_url`):
  <https://learn.microsoft.com/en-us/microsoft-edge/extensions/developer-guide/port-chrome-extension>
- Native messaging: the store's id differs from the sideloaded one, and both stores' ids go in `allowed_origins`:
  <https://learn.microsoft.com/en-us/microsoft-edge/extensions/developer-guide/native-messaging>

**Firefox (AMO)**

- Submitting: <https://extensionworkshop.com/documentation/publish/submitting-an-add-on/>
- The listing (summary of 250 characters, screenshots of 1280x800, the privacy policy as text):
  <https://extensionworkshop.com/documentation/develop/create-an-appealing-listing/>
- Policies (native messaging counts as transmitting data; no remote code; source code):
  <https://extensionworkshop.com/documentation/publish/add-on-policies/>
- `data_collection_permissions`, required of new extensions since 2025-11-03, shown by Firefox 140 and newer:
  <https://extensionworkshop.com/documentation/develop/firefox-builtin-data-consent/>,
  <https://blog.mozilla.org/addons/2025/10/23/data-collection-consent-changes-for-new-firefox-extensions/>
- `gecko.id` (required for Manifest V3, AMO does not assign one), `strict_min_version`, desktop only without
  `gecko_android`: <https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/browser_specific_settings>
- Two-step authentication for developers: <https://blog.mozilla.org/addons/2021/03/11/two-factor-authentication-required-for-extension-developers>

**Not confirmed in the stores' own documentation** (from experience of the dashboards; check on screen):

- that Partner Center shows the **CRX ID** under "Extension identity" before the first publication (the
  documentation only names the Product ID there);
- Edge's list of categories, and that it lists one row per language of the package and lets each be removed;
- the exact wording of the data boxes and certifications in Chrome's and Edge's forms (Google's page shows them only
  as a picture);
- whether Chrome still refuses a new item whose manifest has `key` (reports differ; the build removes it either
  way), and whether Edge does;
- how long each review takes.
