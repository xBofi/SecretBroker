# The website's images

Every image the site uses is listed here. Replace a file with one of the **same name and proportions** and the
pages pick it up: nothing else needs editing (`python tools/check_site.py` confirms every page still finds its
images). Each language has its own folder, `en/` and `es/`, with the same file names in both.

## 1. Demo-vault screenshots (`<name>-light.png`, `<name>-dark.png`)

Made by `tools/make_screenshots.py` from a demo vault with made-up data: the whole window, 2400×1520 px (1200×760
at 2×), one light and one dark. The page shows the one that matches its theme. Pages marked *focus* zoom into the
middle of the window, where the app puts its dialogs, so the dialog must stay centred.

```
python tools/make_screenshots.py --lang es --out site/img
python tools/make_screenshots.py --lang en --out site/img
# Refresh selected screens in both languages without overwriting any other pair:
python tools/make_screenshots.py --out site/img --only setup-unlock --only connect-ai --only import --only extension-pair
```

Regenerate both languages when the app changes. Each run switches the real interface to that language and uses
matching demo names, notes, account holders and website addresses; no image translation or retouching is needed.

| File (`-light` and `-dark`) | Screen and state | Used in |
|---|---|---|
| `vault` | Credentials, a website login open with its 2FA code showing | Home (hero); Guide › Two-step codes |
| `approval` | The dialog “… wants to use a credential” over the vault, with Deny / Just this once / Allow for 24 hours | Home (“The idea”, *focus*); Developers › How approvals work (*focus*); the Open Graph images |
| `generator` | Password generator, a random password rated Excellent | Home, track 01 (*focus*) |
| `rotate` | Rotate with help, step 1 “Where it's used”, for an API key | Home, track 02 (*focus*); Developers › Rotate a key (*focus*) |
| `new-item` | “New credential” with everyday items first and developer types below | Guide › Add your first password (*focus*) |
| `welcome` | The first screen of the setup, with “Get started” | Guide › Create your vault |
| `setup-unlock` | Setup step 3, with the real choices for how to open the vault each day | Guide › Create your vault |
| `connect-ai` | The last setup step, with detected AI clients, a phrase to try and the first-request status | Developers › Connect your AI |
| `import` | “Import from another manager”, with Bitwarden selected and its export instructions | Guide › Import |
| `extension-pair` | “Connect Chrome?” with a six-digit code; generated through the isolated demo service, then rejected | Guide › Fill in passwords in your browser |
| `settings` | Settings, the Security section | Guide › Locking and unlocking |
| `api-key` | Credentials, an API key open with its “Instructions for the AI” | Developers › Add an API key |
| `ai-access` | AI access: connected clients, “Pause the AI”, “What the AI can do” | Developers › How approvals work |
| `appearance` | Settings scrolled to Appearance: language, theme, all palettes, text size, density and motion | Available for the personalization guide |
| `visa` | Payment card, with its holder and expiry; secret fields stay hidden | Available for everyday-item examples |
| `identity` | Passport, with its document type, name, country and expiry | Available for everyday-item examples |
| `wifi` | Home Wi-Fi, with its network name and security type | Available for everyday-item examples |
| `bank` | Bank account, with its bank and account holder | Available for everyday-item examples |
| `note` | Secure note; its contents stay hidden | Available for everyday-item examples |
| `license` | Software license, with its product and registered owner | Available for everyday-item examples |

## 2. Stand-ins from the GUI test suite (`<name>.png`)

Screens `tools/make_screenshots.py` does not photograph yet. These come from `tests/test_gui.py`'s own screenshots
(test data such as “Echo API” and “Bob”), dark theme only, at 1× (blurry on high-density screens). Dialogs are
cropped to the dialog's own border; the page puts them on a neutral stage. To replace one, add the screen to
`tools/make_screenshots.py` (then it becomes a `-light`/`-dark` pair and the page needs its `<figure>` changed to
the two-image form the other screenshots use), or capture it by hand at the size below, or larger with the same
proportions.

| File | Screen and state | Size (px) | `en/` is | `es/` is | Used in |
|---|---|---|---|---|---|
| `share.png` | “Share …” dialog, tab “With a person”, a person and a permission chosen | 480×520 | English | Spanish | Home, track 03; Teams › Share credentials |
| `team-people.png` | Team › People: the invite field and the list of members | 1104×701 | English | Spanish | Teams › Invite people |
| `server-panel.png` | Team › Server › Overview | 1104×701 | English | Spanish | Teams › Run the server from the app |
| `health.png` | Health: the score, credentials to change, “Copies found” (window cut above the list of files) | 1104×655 | English | Spanish | Guide › Check your passwords' health; Developers › Find keys that leaked |
| `env-import.png` | “Import a project's .env” dialog with keys ticked | 680×526 (en), 680×470 (es) | English | Spanish | Developers › Move a project's .env |
| `move-pc.png` | “Move to another PC” dialog | 680×630 | English | Spanish | Guide › Backups |
| `extension-install.png` | “Install the extension” dialog, Chrome tab | 480×653 | English | Spanish | Guide › Fill in passwords in your browser |
| `lock.png` | The lock screen (centre of the window) with “Forgot your master password?” | 440×360 | English | Spanish | Guide › If you forget the master password |

Older single-file captures of `extension-pair`, `import`, `setup-unlock` and `connect-ai` are superseded by the
localized demo-vault pairs above. The pairing capture never accepts the demo request or connects a real browser.

Two of these were retouched because the test's capture showed a folder of the machine it ran on: in
`env-import.png` the project's path next to “.env” is painted over, and in `extension-install.png` the extension's
folder reads `C:\Program Files\SecretBroker\extension`, which is where an installed app has it. Real captures from
an installed app need no retouching.

## 3. Icons and sharing images

| File | What | Size |
|---|---|---|
| `icon.svg` | The app's icon as a vector (same shapes as `tools/make_icon.py`): the browser tab icon | vector |
| `icon-180.png`, `icon-512.png` | The same, rendered by `tools/make_icon.py`: the icon for phones' home screens | 180×180, 512×512 |
| `../favicon.ico` | The same, 16, 32 and 48 px: the tab icon for browsers that ignore SVG | multi-size |
| `og-en.png`, `og-es.png` | The image shown when the site is shared in a chat or a social network: the name, the headline and the approval dialog (dark) | 1200×630 |
