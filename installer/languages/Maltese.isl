; *** Inno Setup version 6.5.0+ Maltese messages ***
; Translated for SecretBroker (https://github.com/xBofi/SecretBroker); distributed under the Inno Setup license, like Default.isl.
;
; Note: When translating this text, do not add periods (.) to the end of
; messages that didn't have them already, because on those messages Inno
; Setup adds the periods automatically (appending a period would result in
; two periods being displayed).

[LangOptions]
; The following three entries are very important. Be sure to read and
; understand the '[LangOptions] section' topic in the help file.
LanguageName=Malti
LanguageID=$043A
; LanguageCodePage should always be set if possible, even if this file is Unicode
; For Maltese it's set to zero because the Maltese letters (ċ, ġ, ħ, ż) have no Windows ANSI code page; this file is Unicode
LanguageCodePage=0
; If the language you are translating to requires special font faces or
; sizes, uncomment any of the following entries and change them accordingly.
;DialogFontName=
;DialogFontSize=9
;DialogFontBaseScaleWidth=7
;DialogFontBaseScaleHeight=15
;WelcomeFontName=Segoe UI
;WelcomeFontSize=14

[Messages]

; *** Application titles
SetupAppTitle=Installazzjoni
SetupWindowTitle=Installazzjoni - %1
UninstallAppTitle=Tneħħija
UninstallAppFullTitle=Tneħħija ta' %1

; *** Misc. common
InformationTitle=Informazzjoni
ConfirmTitle=Ikkonferma
ErrorTitle=Żball

; *** SetupLdr messages
SetupLdrStartupMessage=Dan se jinstalla %1. Trid tkompli?
LdrCannotCreateTemp=Ma setax jinħoloq fajl temporanju. L-installazzjoni twaqqfet
LdrCannotExecTemp=Ma setax jitħaddem fajl fid-direttorju temporanju. L-installazzjoni twaqqfet
HelpTextNote=

; *** Startup error messages
LastErrorMessage=%1.%n%nŻball %2: %3
SetupFileMissing=Il-fajl %1 nieqes mid-direttorju tal-installazzjoni. Jekk jogħġbok solvi l-problema jew ikseb kopja ġdida tal-programm.
SetupFileCorrupt=Il-fajls tal-installazzjoni huma korrotti. Jekk jogħġbok ikseb kopja ġdida tal-programm.
SetupFileCorruptOrWrongVer=Il-fajls tal-installazzjoni huma korrotti, jew mhumiex kompatibbli ma' din il-verżjoni tal-Installazzjoni. Jekk jogħġbok solvi l-problema jew ikseb kopja ġdida tal-programm.
InvalidParameter=Ġie mgħoddi parametru mhux validu fil-linja tal-kmand:%n%n%1
SetupAlreadyRunning=L-Installazzjoni diġà għaddejja.
WindowsVersionNotSupported=Dan il-programm ma jappoġġjax il-verżjoni tal-Windows li qed jaħdem biha dan il-PC.
WindowsServicePackRequired=Dan il-programm jeħtieġ %1 Service Pack %2 jew aktar ġdid.
NotOnThisPlatform=Dan il-programm ma jaħdimx fuq %1.
OnlyOnThisPlatform=Dan il-programm irid jitħaddem fuq %1.
OnlyOnTheseArchitectures=Dan il-programm jista' jiġi installat biss fuq verżjonijiet tal-Windows magħmula għal dawn l-arkitetturi tal-proċessur:%n%n%1
WinVersionTooLowError=Dan il-programm jeħtieġ %1 verżjoni %2 jew aktar ġdida.
WinVersionTooHighError=Dan il-programm ma jistax jiġi installat fuq %1 verżjoni %2 jew aktar ġdida.
AdminPrivilegesRequired=Trid tkun dħalt bħala amministratur biex tinstalla dan il-programm.
PowerUserPrivilegesRequired=Trid tkun dħalt bħala amministratur jew bħala membru tal-grupp Power Users biex tinstalla dan il-programm.
SetupAppRunningError=L-Installazzjoni sabet li %1 bħalissa qed jaħdem.%n%nJekk jogħġbok agħlaq kull kopja tiegħu issa, imbagħad ikklikkja OK biex tkompli, jew Ikkanċella biex toħroġ.
UninstallAppRunningError=It-Tneħħija sabet li %1 bħalissa qed jaħdem.%n%nJekk jogħġbok agħlaq kull kopja tiegħu issa, imbagħad ikklikkja OK biex tkompli, jew Ikkanċella biex toħroġ.

; *** Startup questions
PrivilegesRequiredOverrideTitle=Agħżel il-Mod tal-Installazzjoni
PrivilegesRequiredOverrideInstruction=Agħżel il-mod tal-installazzjoni
PrivilegesRequiredOverrideText1=%1 jista' jiġi installat għall-utenti kollha (jeħtieġ privileġġi ta' amministratur), jew għalik biss.
PrivilegesRequiredOverrideText2=%1 jista' jiġi installat għalik biss, jew għall-utenti kollha (jeħtieġ privileġġi ta' amministratur).
PrivilegesRequiredOverrideAllUsers=Installa għall-utenti &kollha
PrivilegesRequiredOverrideAllUsersRecommended=Installa għall-utenti &kollha (rakkomandat)
PrivilegesRequiredOverrideCurrentUser=Installa għalija &biss
PrivilegesRequiredOverrideCurrentUserRecommended=Installa għalija &biss (rakkomandat)

; *** Misc. errors
ErrorCreatingDir=L-Installazzjoni ma setgħetx toħloq id-direttorju "%1"
ErrorTooManyFilesInDir=Ma setax jinħoloq fajl fid-direttorju "%1" għax fih wisq fajls

; *** Setup common messages
ExitSetupTitle=Oħroġ mill-Installazzjoni
ExitSetupMessage=L-Installazzjoni mhix lesta. Jekk toħroġ issa, il-programm mhux se jiġi installat.%n%nTista' terġa' tħaddem l-Installazzjoni f'ħin ieħor biex tlesti l-installazzjoni.%n%nToħroġ mill-Installazzjoni?
AboutSetupMenuItem=&Dwar l-Installazzjoni...
AboutSetupTitle=Dwar l-Installazzjoni
AboutSetupMessage=%1 verżjoni %2%n%3%n%nIl-paġna ewlenija ta' %1:%n%4
AboutSetupNote=
TranslatorNote=

; *** Buttons
ButtonBack=< &Lura
ButtonNext=Li &jmiss >
ButtonInstall=&Installa
ButtonOK=OK
ButtonCancel=Ikkanċella
ButtonYes=&Iva
ButtonYesToAll=Iva &għal kollox
ButtonNo=&Le
ButtonNoToAll=L&e għal kollox
ButtonFinish=Le&st
ButtonBrowse=&Fittex...
ButtonWizardBrowse=F&ittex...
ButtonNewFolder=&Oħloq Folder Ġdid

; *** "Select Language" dialog messages
SelectLanguageTitle=Agħżel il-Lingwa tal-Installazzjoni
SelectLanguageLabel=Agħżel il-lingwa li trid tuża matul l-installazzjoni.

; *** Common wizard text
ClickNext=Ikklikkja Li jmiss biex tkompli, jew Ikkanċella biex toħroġ mill-Installazzjoni.
BeveledLabel=
BrowseDialogTitle=Fittex Folder
BrowseDialogLabel=Agħżel folder mil-lista hawn taħt, imbagħad ikklikkja OK.
NewFolderName=Folder Ġdid

; *** "Welcome" wizard page
WelcomeLabel1=Merħba fil-Gwida tal-Installazzjoni ta' [name]
WelcomeLabel2=Dan se jinstalla [name/ver] fuq dan il-PC.%n%nHuwa rakkomandat li tagħlaq l-applikazzjonijiet l-oħra kollha qabel tkompli.

; *** "Password" wizard page
WizardPassword=Password
PasswordLabel1=Din l-installazzjoni hija protetta b'password.
PasswordLabel3=Jekk jogħġbok daħħal il-password, imbagħad ikklikkja Li jmiss biex tkompli. Il-passwords jagħmlu distinzjoni bejn ittri kbar u żgħar.
PasswordEditLabel=&Password:
IncorrectPassword=Il-password li daħħalt mhix korretta. Jekk jogħġbok erġa' pprova.

; *** "License Agreement" wizard page
WizardLicense=Ftehim tal-Liċenzja
LicenseLabel=Jekk jogħġbok aqra l-informazzjoni importanti li ġejja qabel tkompli.
LicenseLabel3=Jekk jogħġbok aqra l-Ftehim tal-Liċenzja li ġej. Trid taċċetta t-termini ta' dan il-ftehim qabel tkompli bl-installazzjoni.
LicenseAccepted=&Naċċetta l-ftehim
LicenseNotAccepted=&Ma naċċettax il-ftehim

; *** "Information" wizard pages
WizardInfoBefore=Informazzjoni
InfoBeforeLabel=Jekk jogħġbok aqra l-informazzjoni importanti li ġejja qabel tkompli.
InfoBeforeClickLabel=Meta tkun lest biex tkompli bl-Installazzjoni, ikklikkja Li jmiss.
WizardInfoAfter=Informazzjoni
InfoAfterLabel=Jekk jogħġbok aqra l-informazzjoni importanti li ġejja qabel tkompli.
InfoAfterClickLabel=Meta tkun lest biex tkompli bl-Installazzjoni, ikklikkja Li jmiss.

; *** "User Information" wizard page
WizardUserInfo=Informazzjoni dwar l-Utent
UserInfoDesc=Jekk jogħġbok daħħal l-informazzjoni tiegħek.
UserInfoName=&Isem l-utent:
UserInfoOrg=&Organizzazzjoni:
UserInfoSerial=&Numru tas-serje:
UserInfoNameRequired=Trid iddaħħal isem.

; *** "Select Destination Location" wizard page
WizardSelectDir=Agħżel fejn se jiġi installat
SelectDirDesc=Fejn għandu jiġi installat [name]?
SelectDirLabel3=L-Installazzjoni se tinstalla [name] f'dan il-folder.
SelectDirBrowseLabel=Biex tkompli, ikklikkja Li jmiss. Jekk tixtieq tagħżel folder ieħor, ikklikkja Fittex.
DiskSpaceGBLabel=Huma meħtieġa mill-inqas [gb] GB ta' spazju ħieles fuq id-diska.
DiskSpaceMBLabel=Huma meħtieġa mill-inqas [mb] MB ta' spazju ħieles fuq id-diska.
CannotInstallToNetworkDrive=L-Installazzjoni ma tistax tinstalla fuq drive tan-netwerk.
CannotInstallToUNCPath=L-Installazzjoni ma tistax tinstalla fuq path UNC.
InvalidPath=Trid iddaħħal path sħiħ bl-ittra tad-drive; pereżempju:%n%nC:\APP%n%njew path UNC f'din il-forma:%n%n\\server\share
InvalidDrive=Id-drive jew is-share UNC li għażilt ma jeżistix jew mhux aċċessibbli. Jekk jogħġbok agħżel ieħor.
DiskSpaceWarningTitle=M'hemmx Biżżejjed Spazju fuq id-Diska
DiskSpaceWarning=L-Installazzjoni teħtieġ mill-inqas %1 KB ta' spazju ħieles biex tinstalla, iżda d-drive magħżul għandu biss %2 KB disponibbli.%n%nTrid tkompli xorta waħda?
DirNameTooLong=L-isem tal-folder jew il-path huwa twil wisq.
InvalidDirName=L-isem tal-folder mhux validu.
BadDirName32=L-ismijiet tal-folders ma jistgħux ikun fihom l-ebda wieħed minn dawn il-karattri:%n%n%1
DirExistsTitle=Il-Folder Jeżisti
DirExists=Il-folder:%n%n%1%n%ndiġà jeżisti. Trid tinstalla f'dak il-folder xorta waħda?
DirDoesntExistTitle=Il-Folder Ma Jeżistix
DirDoesntExist=Il-folder:%n%n%1%n%nma jeżistix. Trid li jinħoloq il-folder?

; *** "Select Components" wizard page
WizardSelectComponents=Agħżel il-Komponenti
SelectComponentsDesc=Liema komponenti għandhom jiġu installati?
SelectComponentsLabel2=Agħżel il-komponenti li trid tinstalla; neħħi l-marka mill-komponenti li ma tridx tinstalla. Ikklikkja Li jmiss meta tkun lest biex tkompli.
FullInstallation=Installazzjoni sħiħa
; if possible don't translate 'Compact' as 'Minimal' (I mean 'Minimal' in your language)
CompactInstallation=Installazzjoni kompatta
CustomInstallation=Installazzjoni personalizzata
NoUninstallWarningTitle=Il-Komponenti Jeżistu
NoUninstallWarning=L-Installazzjoni sabet li dawn il-komponenti diġà huma installati fuq dan il-PC:%n%n%1%n%nJekk tneħħi l-għażla ta' dawn il-komponenti, ma jitneħħewx.%n%nTrid tkompli xorta waħda?
ComponentSize1=%1 KB
ComponentSize2=%1 MB
ComponentsDiskSpaceGBLabel=L-għażla attwali teħtieġ mill-inqas [gb] GB ta' spazju fuq id-diska.
ComponentsDiskSpaceMBLabel=L-għażla attwali teħtieġ mill-inqas [mb] MB ta' spazju fuq id-diska.

; *** "Select Additional Tasks" wizard page
WizardSelectTasks=Agħżel Kompiti Addizzjonali
SelectTasksDesc=Liema kompiti addizzjonali għandhom isiru?
SelectTasksLabel2=Agħżel il-kompiti addizzjonali li tixtieq li tagħmel l-Installazzjoni waqt li tinstalla [name], imbagħad ikklikkja Li jmiss.

; *** "Select Start Menu Folder" wizard page
WizardSelectProgramGroup=Agħżel il-Folder tal-Menu Start
SelectStartMenuFolderDesc=Fejn għandha tpoġġi l-Installazzjoni x-shortcuts tal-programm?
SelectStartMenuFolderLabel3=L-Installazzjoni se toħloq ix-shortcuts tal-programm f'dan il-folder tal-Menu Start.
SelectStartMenuFolderBrowseLabel=Biex tkompli, ikklikkja Li jmiss. Jekk tixtieq tagħżel folder ieħor, ikklikkja Fittex.
MustEnterGroupName=Trid iddaħħal isem għall-folder.
GroupNameTooLong=L-isem tal-folder jew il-path huwa twil wisq.
InvalidGroupName=L-isem tal-folder mhux validu.
BadGroupName=L-isem tal-folder ma jista' jkun fih l-ebda wieħed minn dawn il-karattri:%n%n%1
NoProgramGroupCheck2=&Toħloqx folder fil-Menu Start

; *** "Ready to Install" wizard page
WizardReady=Lest biex Jinstalla
ReadyLabel1=L-Installazzjoni issa lesta biex tibda tinstalla [name] fuq dan il-PC.
ReadyLabel2a=Ikklikkja Installa biex tkompli bl-installazzjoni, jew ikklikkja Lura jekk trid terġa' tara jew tibdel xi settings.
ReadyLabel2b=Ikklikkja Installa biex tkompli bl-installazzjoni.
ReadyMemoUserInfo=Informazzjoni dwar l-utent:
ReadyMemoDir=Fejn se jiġi installat:
ReadyMemoType=Tip ta' installazzjoni:
ReadyMemoComponents=Komponenti magħżula:
ReadyMemoGroup=Folder tal-Menu Start:
ReadyMemoTasks=Kompiti addizzjonali:

; *** TDownloadWizardPage wizard page and DownloadTemporaryFile
DownloadingLabel2=Qed jitniżżlu l-fajls...
ButtonStopDownload=&Waqqaf it-tniżżil
StopDownload=Żgur li trid twaqqaf it-tniżżil?
ErrorDownloadAborted=It-tniżżil twaqqaf
ErrorDownloadFailed=It-tniżżil falla: %1 %2
ErrorDownloadSizeFailed=Ma setax jinkiseb id-daqs: %1 %2
ErrorProgress=Progress mhux validu: %1 minn %2
ErrorFileSize=Daqs tal-fajl mhux validu: mistenni %1, misjub %2

; *** TExtractionWizardPage wizard page and ExtractArchive
ExtractingLabel=Qed jiġu estratti l-fajls...
ButtonStopExtraction=&Waqqaf l-estrazzjoni
StopExtraction=Żgur li trid twaqqaf l-estrazzjoni?
ErrorExtractionAborted=L-estrazzjoni twaqqfet
ErrorExtractionFailed=L-estrazzjoni falliet: %1

; *** Archive extraction failure details
ArchiveIncorrectPassword=Il-password mhix korretta
ArchiveIsCorrupted=L-arkivju huwa korrott
ArchiveUnsupportedFormat=Il-format tal-arkivju mhux appoġġjat

; *** "Preparing to Install" wizard page
WizardPreparing=Qed Jipprepara biex Jinstalla
PreparingDesc=L-Installazzjoni qed tipprepara biex tinstalla [name] fuq dan il-PC.
PreviousInstallNotCompleted=L-installazzjoni/tneħħija ta' programm preċedenti ma tlestietx. Ikollok terġa' tibda l-PC biex titlesta dik l-installazzjoni.%n%nWara li terġa' tibda l-PC, erġa' ħaddem l-Installazzjoni biex tlesti l-installazzjoni ta' [name].
CannotContinue=L-Installazzjoni ma tistax tkompli. Jekk jogħġbok ikklikkja Ikkanċella biex toħroġ.
ApplicationsFound=L-applikazzjonijiet li ġejjin qed jużaw fajls li l-Installazzjoni trid taġġorna. Huwa rakkomandat li tħalli l-Installazzjoni tagħlaq dawn l-applikazzjonijiet awtomatikament.
ApplicationsFound2=L-applikazzjonijiet li ġejjin qed jużaw fajls li l-Installazzjoni trid taġġorna. Huwa rakkomandat li tħalli l-Installazzjoni tagħlaq dawn l-applikazzjonijiet awtomatikament. Meta titlesta l-installazzjoni, l-Installazzjoni se tipprova terġa' tibda l-applikazzjonijiet.
CloseApplications=&Agħlaq l-applikazzjonijiet awtomatikament
DontCloseApplications=&Tagħlaqx l-applikazzjonijiet
ErrorCloseApplications=L-Installazzjoni ma setgħetx tagħlaq l-applikazzjonijiet kollha awtomatikament. Huwa rakkomandat li tagħlaq l-applikazzjonijiet kollha li qed jużaw fajls li l-Installazzjoni trid taġġorna qabel tkompli.
PrepareToInstallNeedsRestart=L-Installazzjoni trid terġa' tibda l-PC. Wara li terġa' tibda l-PC, erġa' ħaddem l-Installazzjoni biex tlesti l-installazzjoni ta' [name].%n%nTrid terġa' tibdih issa?

; *** "Installing" wizard page
WizardInstalling=Qed Jinstalla
InstallingLabel=Jekk jogħġbok stenna sakemm l-Installazzjoni tinstalla [name] fuq dan il-PC.

; *** "Setup Completed" wizard page
FinishedHeadingLabel=Qed titlesta l-Gwida tal-Installazzjoni ta' [name]
FinishedLabelNoIcons=L-Installazzjoni lestiet l-installazzjoni ta' [name] fuq dan il-PC.
FinishedLabel=L-Installazzjoni lestiet l-installazzjoni ta' [name] fuq dan il-PC. L-applikazzjoni tista' tinfetaħ billi tagħżel ix-shortcuts installati.
ClickFinish=Ikklikkja Lest biex toħroġ mill-Installazzjoni.
FinishedRestartLabel=Biex titlesta l-installazzjoni ta' [name], l-Installazzjoni trid terġa' tibda l-PC. Trid terġa' tibdih issa?
FinishedRestartMessage=Biex titlesta l-installazzjoni ta' [name], l-Installazzjoni trid terġa' tibda l-PC.%n%nTrid terġa' tibdih issa?
ShowReadmeCheck=Iva, nixtieq nara l-fajl README
YesRadio=&Iva, erġa' ibda l-PC issa
NoRadio=&Le, se nerġa' nibda l-PC aktar tard
; used for example as 'Run MyProg.exe'
RunEntryExec=Ħaddem %1
; used for example as 'View Readme.txt'
RunEntryShellExec=Ara %1

; *** "Setup Needs the Next Disk" stuff
ChangeDiskTitle=L-Installazzjoni Teħtieġ id-Diska li Jmiss
SelectDiskLabel2=Jekk jogħġbok daħħal id-Diska %1 u kklikkja OK.%n%nJekk il-fajls ta' din id-diska jinsabu f'folder ieħor minbarra dak muri hawn taħt, daħħal il-path korrett jew ikklikkja Fittex.
PathLabel=&Path:
FileNotInDir2=Il-fajl "%1" ma nstabx f'"%2". Jekk jogħġbok daħħal id-diska t-tajba jew agħżel folder ieħor.
SelectDirectoryLabel=Jekk jogħġbok speċifika fejn tinsab id-diska li jmiss.

; *** Installation phase messages
SetupAborted=L-Installazzjoni ma tlestietx.%n%nJekk jogħġbok solvi l-problema u erġa' ħaddem l-Installazzjoni.
AbortRetryIgnoreSelectAction=Agħżel azzjoni
AbortRetryIgnoreRetry=&Erġa' pprova
AbortRetryIgnoreIgnore=&Injora l-iżball u kompli
AbortRetryIgnoreCancel=Ikkanċella l-installazzjoni
RetryCancelSelectAction=Agħżel azzjoni
RetryCancelRetry=&Erġa' pprova
RetryCancelCancel=Ikkanċella

; *** Installation status messages
StatusClosingApplications=Qed jingħalqu l-applikazzjonijiet...
StatusCreateDirs=Qed jinħolqu d-direttorji...
StatusExtractFiles=Qed jiġu estratti l-fajls...
StatusDownloadFiles=Qed jitniżżlu l-fajls...
StatusCreateIcons=Qed jinħolqu x-shortcuts...
StatusCreateIniEntries=Qed jinħolqu l-entrati INI...
StatusCreateRegistryEntries=Qed jinħolqu l-entrati tar-reġistru...
StatusRegisterFiles=Qed jiġu rreġistrati l-fajls...
StatusSavingUninstall=Qed tiġi ssejvjata l-informazzjoni għat-tneħħija...
StatusRunProgram=Qed titlesta l-installazzjoni...
StatusRestartingApplications=L-applikazzjonijiet qed jerġgħu jinbdew...
StatusRollback=Qed jitreġġgħu lura l-bidliet...

; *** Misc. errors
ErrorInternal2=Żball intern: %1
ErrorFunctionFailedNoCode=%1 falla
ErrorFunctionFailed=%1 falla; kodiċi %2
ErrorFunctionFailedWithMessage=%1 falla; kodiċi %2.%n%3
ErrorExecutingProgram=Ma setax jitħaddem il-fajl:%n%1

; *** Registry errors
ErrorRegOpenKey=Żball fil-ftuħ taċ-ċavetta tar-reġistru:%n%1\%2
ErrorRegCreateKey=Żball fil-ħolqien taċ-ċavetta tar-reġistru:%n%1\%2
ErrorRegWriteKey=Żball fil-kitba fiċ-ċavetta tar-reġistru:%n%1\%2

; *** INI errors
ErrorIniEntry=Żball fil-ħolqien ta' entrata INI fil-fajl "%1".

; *** File copying errors
FileAbortRetryIgnoreSkipNotRecommended=&Aqbeż dan il-fajl (mhux rakkomandat)
FileAbortRetryIgnoreIgnoreNotRecommended=&Injora l-iżball u kompli (mhux rakkomandat)
SourceIsCorrupted=Il-fajl tas-sors huwa korrott
SourceDoesntExist=Il-fajl tas-sors "%1" ma jeżistix
SourceVerificationFailed=Il-verifika tal-fajl tas-sors falliet: %1
VerificationSignatureDoesntExist=Il-fajl tal-firma "%1" ma jeżistix
VerificationSignatureInvalid=Il-fajl tal-firma "%1" mhux validu
VerificationKeyNotFound=Il-fajl tal-firma "%1" juża ċavetta mhux magħrufa
VerificationFileNameIncorrect=L-isem tal-fajl mhux korrett
VerificationFileTagIncorrect=It-tag tal-fajl mhux korrett
VerificationFileSizeIncorrect=Id-daqs tal-fajl mhux korrett
VerificationFileHashIncorrect=Il-hash tal-fajl mhux korrett
ExistingFileReadOnly2=Il-fajl eżistenti ma setax jiġi sostitwit għax huwa mmarkat bħala read-only.
ExistingFileReadOnlyRetry=&Neħħi l-attribut read-only u erġa' pprova
ExistingFileReadOnlyKeepExisting=Ż&omm il-fajl eżistenti
ErrorReadingExistingDest=Seħħ żball waqt li kien qed jinqara l-fajl eżistenti:
FileExistsSelectAction=Agħżel azzjoni
FileExists2=Il-fajl diġà jeżisti.
FileExistsOverwriteExisting=&Ikteb fuq il-fajl eżistenti
FileExistsKeepExisting=Ż&omm il-fajl eżistenti
FileExistsOverwriteOrKeepAll=&Agħmel l-istess għall-kunflitti li jmiss
ExistingFileNewerSelectAction=Agħżel azzjoni
ExistingFileNewer2=Il-fajl eżistenti huwa aktar ġdid minn dak li l-Installazzjoni qed tipprova tinstalla.
ExistingFileNewerOverwriteExisting=&Ikteb fuq il-fajl eżistenti
ExistingFileNewerKeepExisting=Ż&omm il-fajl eżistenti (rakkomandat)
ExistingFileNewerOverwriteOrKeepAll=&Agħmel l-istess għall-kunflitti li jmiss
ErrorChangingAttr=Seħħ żball waqt li kienu qed jinbidlu l-attributi tal-fajl eżistenti:
ErrorCreatingTemp=Seħħ żball waqt li kien qed jinħoloq fajl fid-direttorju tad-destinazzjoni:
ErrorReadingSource=Seħħ żball waqt li kien qed jinqara l-fajl tas-sors:
ErrorCopying=Seħħ żball waqt li kien qed jiġi kkupjat fajl:
ErrorDownloading=Seħħ żball waqt li kien qed jitniżżel fajl:
ErrorExtracting=Seħħ żball waqt li kien qed jiġi estratt arkivju:
ErrorReplacingExistingFile=Seħħ żball waqt li kien qed jiġi sostitwit il-fajl eżistenti:
ErrorRestartReplace=RestartReplace falla:
ErrorRenamingTemp=Seħħ żball waqt li kien qed jinbidel l-isem ta' fajl fid-direttorju tad-destinazzjoni:
ErrorRegisterServer=Ma setax jiġi rreġistrat id-DLL/OCX: %1
ErrorRegSvr32Failed=RegSvr32 falla bil-kodiċi tal-ħruġ %1
ErrorRegisterTypeLib=Ma setgħetx tiġi rreġistrata l-librerija tat-tipi: %1

; *** Uninstall display name markings
; used for example as 'My Program (32-bit)'
UninstallDisplayNameMark=%1 (%2)
; used for example as 'My Program (32-bit, All users)'
UninstallDisplayNameMarks=%1 (%2, %3)
UninstallDisplayNameMark32Bit=32-bit
UninstallDisplayNameMark64Bit=64-bit
UninstallDisplayNameMarkAllUsers=L-utenti kollha
UninstallDisplayNameMarkCurrentUser=L-utent attwali

; *** Post-installation errors
ErrorOpeningReadme=Seħħ żball waqt li kien qed jinfetaħ il-fajl README.
ErrorRestartingComputer=L-Installazzjoni ma setgħetx terġa' tibda l-PC. Jekk jogħġbok agħmel dan int.

; *** Uninstaller messages
UninstallNotFound=Il-fajl "%1" ma jeżistix. Ma jistax jitneħħa.
UninstallOpenError=Il-fajl "%1" ma setax jinfetaħ. Ma jistax jitneħħa
UninstallUnsupportedVer=Il-fajl tal-log tat-tneħħija "%1" huwa f'format li din il-verżjoni tal-programm tat-tneħħija ma tagħrafx. Ma jistax jitneħħa
UninstallUnknownEntry=Instabet entrata mhux magħrufa (%1) fil-log tat-tneħħija
ConfirmUninstall=Żgur li trid tneħħi għal kollox lil %1 u l-komponenti kollha tiegħu?
UninstallOnlyOnWin64=Din l-installazzjoni tista' titneħħa biss fuq Windows ta' 64-bit.
OnlyAdminCanUninstall=Din l-installazzjoni tista' titneħħa biss minn utent bi privileġġi ta' amministratur.
UninstallStatusLabel=Jekk jogħġbok stenna sakemm %1 jitneħħa minn dan il-PC.
UninstalledAll=%1 tneħħa b'suċċess minn dan il-PC.
UninstalledMost=It-tneħħija ta' %1 lesta.%n%nXi elementi ma setgħux jitneħħew. Dawn tista' tneħħihom int.
UninstalledAndNeedsRestart=Biex titlesta t-tneħħija ta' %1, il-PC irid jerġa' jinbeda.%n%nTrid terġa' tibdih issa?
UninstallDataCorrupted=Il-fajl "%1" huwa korrott. Ma jistax jitneħħa

; *** Uninstallation phase messages
ConfirmDeleteSharedFileTitle=Tneħħi l-Fajl Kondiviż?
ConfirmDeleteSharedFile2=Is-sistema tindika li l-fajl kondiviż li ġej m'għadu jintuża minn l-ebda programm. Trid li t-Tneħħija tneħħi dan il-fajl kondiviż?%n%nJekk xi programmi għadhom jużaw dan il-fajl u jitneħħa, dawk il-programmi jistgħu ma jaħdmux sew. Jekk m'intix ċert, agħżel Le. Jekk tħalli l-fajl fis-sistema, ma jagħmel l-ebda ħsara.
SharedFileNameLabel=Isem il-fajl:
SharedFileLocationLabel=Post:
WizardUninstalling=Stat tat-Tneħħija
StatusUninstalling=Qed jitneħħa %1...

; *** Shutdown block reasons
ShutdownBlockReasonInstallingApp=Qed jiġi installat %1.
ShutdownBlockReasonUninstallingApp=Qed jitneħħa %1.

; The custom messages below aren't used by Setup itself, but if you make
; use of them in your scripts, you'll want to translate them.

[CustomMessages]

NameAndVersion=%1 verżjoni %2
AdditionalIcons=Shortcuts addizzjonali:
CreateDesktopIcon=Oħloq shortcut fuq id-&Desktop
CreateQuickLaunchIcon=Oħloq shortcut fil-&Quick Launch
ProgramOnTheWeb=%1 fuq il-Web
UninstallProgram=Neħħi %1
LaunchProgram=Iftaħ %1
AssocFileExtension=&Assoċja %1 mal-estensjoni tal-fajl %2
AssocingFileExtension=Qed jiġi assoċjat %1 mal-estensjoni tal-fajl %2...
AutoStartProgramGroupDescription=Bidu:
AutoStartProgram=Iftaħ %1 awtomatikament
AddonHostProgramNotFound=%1 ma nstabx fil-folder li għażilt.%n%nTrid tkompli xorta waħda?
