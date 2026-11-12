# Inno Setup messages files

The Windows installer's wizard texts for the languages Inno Setup 6 doesn't ship a translation for (the others come
from `compiler:Languages\…`; `tools/installer_languages.py` says which file each language uses). All are UTF-8 with
a BOM, which every Unicode Inno Setup 6 reads as such, and translate every message of Inno Setup 6.5+'s `Default.isl`
(the compiler warns about a missing one; `tools/build_installer.ps1` prints its warnings).

## License

Inno Setup's translations are distributed under the Inno Setup license, which allows redistributing them, modified or
not, keeping their copyright notices and marking modified versions as such: it is in
[LICENSE-InnoSetup.txt](LICENSE-InnoSetup.txt) (from <https://github.com/jrsoftware/issrc/blob/main/license.txt>).
Each file keeps its translators' notices and says, at the top, what we changed. Our own translations (Irish, Maltese)
are under the same license, so they can go back upstream.

## Where each file comes from

From [jrsoftware/issrc](https://github.com/jrsoftware/issrc) (Inno Setup's source repository) at commit
`02bbcabce6be6bad738d565d7a02d12b95a45af0` (2026-11-11), under `Files/Languages/`:

| File | Language | Upstream | Our changes |
|---|---|---|---|
| `Basque.isl` | eu | `Unofficial/Basque.isl` | BOM; `ExtractingLabel` added; obsolete `ExtractionLabel` removed |
| `ChineseSimplified.isl` | zh-CN | `ChineseSimplified.isl` (official in the repository, not yet shipped with Inno Setup 6.7.3) | BOM |
| `Croatian.isl` | hr | `Unofficial/Croatian.isl` | BOM |
| `Estonian.isl` | et | `Unofficial/Estonian.isl` (for Inno Setup 5.5.3) | Windows-1257 → UTF-8; the 67 messages added since 5.5.3 translated; 7 obsolete ones removed |
| `Galician.isl` | gl | `Unofficial/Galician.isl` | BOM |
| `Greek.isl` | el | `Unofficial/Greek.isl` | BOM |
| `Latvian.isl` | lv | `Unofficial/Latvian.isl` (for 6.1.0) | the 23 messages added since 6.1 translated; 3 obsolete ones removed |
| `Lithuanian.isl` | lt | `Lithuanian.isl` (official in the repository, not yet shipped with Inno Setup 6.7.3) | BOM |
| `Romanian.isl` | ro | `Unofficial/Romanian.isl` (for 6.1.0) | Windows-1250 → UTF-8; the 23 messages added since 6.1 translated; 3 obsolete ones removed |

Written for SecretBroker from `Default.isl` (Inno Setup 6.7.3), no upstream translation existing:

| File | Language | Notes |
|---|---|---|
| `Irish.isl` | ga | `LanguageID=$083C` (ga-IE). Needs a native speaker's review. |
| `Maltese.isl` | mt | `LanguageID=$043A` (mt-MT), `LanguageCodePage=0` (no ANSI code page has ċ ġ ħ ż). Needs a native speaker's review. |

The messages we added to the upstream files sit at the end of their `[Messages]` section under a
`; *** Added for SecretBroker` comment, so they are easy to send upstream.

To update a file from upstream: take the new version from `Files/Languages/` (or `Unofficial/`), save it as UTF-8
with a BOM, keep our additions only for the messages it still lacks, and update the commit above.
