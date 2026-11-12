; *** Inno Setup version 6.5.0+ Irish messages ***
; Translated for SecretBroker (https://github.com/xBofi/SecretBroker); distributed under the Inno Setup license, like Default.isl.
;
; To download user-contributed translations of this file, go to:
;   https://jrsoftware.org/files/istrans/
;
; Note: When translating this text, do not add periods (.) to the end of
; messages that didn't have them already, because on those messages Inno
; Setup adds the periods automatically (appending a period would result in
; two periods being displayed).

[LangOptions]
; The following three entries are very important. Be sure to read and
; understand the '[LangOptions] section' topic in the help file.
LanguageName=Gaeilge
LanguageID=$083C
; LanguageCodePage should always be set if possible, even if this file is Unicode
LanguageCodePage=1252
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
SetupAppTitle=Suiteáil
SetupWindowTitle=Suiteáil - %1
UninstallAppTitle=Díshuiteáil
UninstallAppFullTitle=Díshuiteáil %1

; *** Misc. common
InformationTitle=Eolas
ConfirmTitle=Deimhnigh
ErrorTitle=Earráid

; *** SetupLdr messages
SetupLdrStartupMessage=Suiteálfar %1 leis seo. An bhfuil fonn ort leanúint ar aghaidh?
LdrCannotCreateTemp=Ní féidir comhad sealadach a chruthú. Cuireadh deireadh leis an tSuiteáil
LdrCannotExecTemp=Ní féidir an comhad san fhillteán sealadach a rith. Cuireadh deireadh leis an tSuiteáil
HelpTextNote=

; *** Startup error messages
LastErrorMessage=%1.%n%nEarráid %2: %3
SetupFileMissing=Tá an comhad %1 ar iarraidh ón bhfillteán suiteála. Ceartaigh an fhadhb nó faigh cóip nua den chlár.
SetupFileCorrupt=Tá comhaid na suiteála truaillithe. Faigh cóip nua den chlár.
SetupFileCorruptOrWrongVer=Tá comhaid na suiteála truaillithe, nó níl siad comhoiriúnach leis an leagan seo den tSuiteáil. Ceartaigh an fhadhb nó faigh cóip nua den chlár.
InvalidParameter=Tugadh paraiméadar neamhbhailí ar an líne ordaithe:%n%n%1
SetupAlreadyRunning=Tá an tSuiteáil ag rith cheana féin.
WindowsVersionNotSupported=Ní thacaíonn an clár seo leis an leagan de Windows atá ar do ríomhaire.
WindowsServicePackRequired=Teastaíonn %1 Pacáiste Seirbhíse %2 nó níos déanaí ón gclár seo.
NotOnThisPlatform=Ní rithfidh an clár seo ar %1.
OnlyOnThisPlatform=Caithfear an clár seo a rith ar %1.
OnlyOnTheseArchitectures=Ní féidir an clár seo a shuiteáil ach ar leaganacha de Windows atá deartha do na hailtireachtaí próiseálaí seo a leanas:%n%n%1
WinVersionTooLowError=Teastaíonn %1 leagan %2 nó níos déanaí ón gclár seo.
WinVersionTooHighError=Ní féidir an clár seo a shuiteáil ar %1 leagan %2 ná níos déanaí.
AdminPrivilegesRequired=Caithfidh tú a bheith logáilte isteach mar riarthóir chun an clár seo a shuiteáil.
PowerUserPrivilegesRequired=Caithfidh tú a bheith logáilte isteach mar riarthóir nó mar bhall den ghrúpa Power Users chun an clár seo a shuiteáil.
SetupAppRunningError=Bhraith an tSuiteáil go bhfuil %1 ag rith faoi láthair.%n%nDún gach cás de anois, ansin cliceáil OK chun leanúint ar aghaidh, nó Cealaigh chun scor.
UninstallAppRunningError=Bhraith an Díshuiteáil go bhfuil %1 ag rith faoi láthair.%n%nDún gach cás de anois, ansin cliceáil OK chun leanúint ar aghaidh, nó Cealaigh chun scor.

; *** Startup questions
PrivilegesRequiredOverrideTitle=Roghnaigh Mód Suiteála
PrivilegesRequiredOverrideInstruction=Roghnaigh mód suiteála
PrivilegesRequiredOverrideText1=Is féidir %1 a shuiteáil do gach úsáideoir (teastaíonn pribhléidí riaracháin), nó duitse amháin.
PrivilegesRequiredOverrideText2=Is féidir %1 a shuiteáil duitse amháin, nó do gach úsáideoir (teastaíonn pribhléidí riaracháin).
PrivilegesRequiredOverrideAllUsers=Suiteáil do &gach úsáideoir
PrivilegesRequiredOverrideAllUsersRecommended=Suiteáil do &gach úsáideoir (molta)
PrivilegesRequiredOverrideCurrentUser=Suiteáil domsa &amháin
PrivilegesRequiredOverrideCurrentUserRecommended=Suiteáil domsa &amháin (molta)

; *** Misc. errors
ErrorCreatingDir=Níorbh fhéidir leis an tSuiteáil an fillteán "%1" a chruthú
ErrorTooManyFilesInDir=Ní féidir comhad a chruthú san fhillteán "%1" mar go bhfuil an iomarca comhad ann

; *** Setup common messages
ExitSetupTitle=Scoir den tSuiteáil
ExitSetupMessage=Níl an tSuiteáil críochnaithe. Má scoireann tú anois, ní shuiteálfar an clár.%n%nIs féidir leat an tSuiteáil a rith arís am éigin eile chun an tsuiteáil a chríochnú.%n%nScoir den tSuiteáil?
AboutSetupMenuItem=&Maidir leis an tSuiteáil...
AboutSetupTitle=Maidir leis an tSuiteáil
AboutSetupMessage=%1 leagan %2%n%3%n%nLeathanach baile %1:%n%4
AboutSetupNote=
TranslatorNote=

; *** Buttons
ButtonBack=< &Siar
ButtonNext=&Ar Aghaidh >
ButtonInstall=&Suiteáil
ButtonOK=OK
ButtonCancel=Cealaigh
ButtonYes=&Tá
ButtonYesToAll=Tá do &Gach Ceann
ButtonNo=&Níl
ButtonNoToAll=Níl do Gach &Ceann
ButtonFinish=&Críochnaigh
ButtonBrowse=&Brabhsáil...
ButtonWizardBrowse=B&rabhsáil...
ButtonNewFolder=Déan Fillteán &Nua

; *** "Select Language" dialog messages
SelectLanguageTitle=Roghnaigh Teanga na Suiteála
SelectLanguageLabel=Roghnaigh an teanga a úsáidfear le linn na suiteála.

; *** Common wizard text
ClickNext=Cliceáil Ar Aghaidh chun leanúint ar aghaidh, nó Cealaigh chun scor den tSuiteáil.
BeveledLabel=
BrowseDialogTitle=Brabhsáil chuig Fillteán
BrowseDialogLabel=Roghnaigh fillteán sa liosta thíos, ansin cliceáil OK.
NewFolderName=Fillteán Nua

; *** "Welcome" wizard page
WelcomeLabel1=Fáilte chuig Draoi Suiteála [name]
WelcomeLabel2=Suiteálfar [name/ver] ar do ríomhaire leis seo.%n%nMoltar duit gach feidhmchlár eile a dhúnadh sula leanann tú ar aghaidh.

; *** "Password" wizard page
WizardPassword=Pasfhocal
PasswordLabel1=Tá an tsuiteáil seo cosanta le pasfhocal.
PasswordLabel3=Tabhair an pasfhocal, ansin cliceáil Ar Aghaidh chun leanúint ar aghaidh. Tá na pasfhocail cásíogair.
PasswordEditLabel=&Pasfhocal:
IncorrectPassword=Níl an pasfhocal a d'iontráil tú ceart. Bain triail eile as.

; *** "License Agreement" wizard page
WizardLicense=Comhaontú Ceadúnais
LicenseLabel=Léigh an t-eolas tábhachtach seo a leanas sula leanann tú ar aghaidh.
LicenseLabel3=Léigh an Comhaontú Ceadúnais seo a leanas. Caithfidh tú glacadh le téarmaí an chomhaontaithe seo sula leanann tú ar aghaidh leis an tsuiteáil.
LicenseAccepted=&Glacaim leis an gcomhaontú
LicenseNotAccepted=&Ní ghlacaim leis an gcomhaontú

; *** "Information" wizard pages
WizardInfoBefore=Eolas
InfoBeforeLabel=Léigh an t-eolas tábhachtach seo a leanas sula leanann tú ar aghaidh.
InfoBeforeClickLabel=Nuair atá tú réidh chun leanúint ar aghaidh leis an tSuiteáil, cliceáil Ar Aghaidh.
WizardInfoAfter=Eolas
InfoAfterLabel=Léigh an t-eolas tábhachtach seo a leanas sula leanann tú ar aghaidh.
InfoAfterClickLabel=Nuair atá tú réidh chun leanúint ar aghaidh leis an tSuiteáil, cliceáil Ar Aghaidh.

; *** "User Information" wizard page
WizardUserInfo=Eolas Úsáideora
UserInfoDesc=Iontráil d'eolas.
UserInfoName=&Ainm Úsáideora:
UserInfoOrg=&Eagraíocht:
UserInfoSerial=&Sraithuimhir:
UserInfoNameRequired=Caithfidh tú ainm a iontráil.

; *** "Select Destination Location" wizard page
WizardSelectDir=Roghnaigh Suíomh Sprice
SelectDirDesc=Cá suiteálfar [name]?
SelectDirLabel3=Suiteálfaidh an tSuiteáil [name] san fhillteán seo a leanas.
SelectDirBrowseLabel=Chun leanúint ar aghaidh, cliceáil Ar Aghaidh. Más mian leat fillteán eile a roghnú, cliceáil Brabhsáil.
DiskSpaceGBLabel=Teastaíonn [gb] GB ar a laghad de spás saor ar an diosca.
DiskSpaceMBLabel=Teastaíonn [mb] MB ar a laghad de spás saor ar an diosca.
CannotInstallToNetworkDrive=Ní féidir leis an tSuiteáil suiteáil ar thiomántán líonra.
CannotInstallToUNCPath=Ní féidir leis an tSuiteáil suiteáil ar chonair UNC.
InvalidPath=Caithfidh tú conair iomlán le litir tiomántáin a iontráil; mar shampla:%n%nC:\APP%n%nnó conair UNC san fhoirm:%n%n\\server\share
InvalidDrive=Níl an tiomántán nó an chomhroinn UNC a roghnaigh tú ann, nó níl rochtain air. Roghnaigh ceann eile.
DiskSpaceWarningTitle=Níl Go Leor Spáis ar an Diosca
DiskSpaceWarning=Teastaíonn %1 KB ar a laghad de spás saor ón tSuiteáil chun suiteáil, ach níl ach %2 KB ar fáil ar an tiomántán roghnaithe.%n%nAn bhfuil fonn ort leanúint ar aghaidh mar sin féin?
DirNameTooLong=Tá ainm an fhillteáin nó an chonair rófhada.
InvalidDirName=Níl ainm an fhillteáin bailí.
BadDirName32=Ní féidir aon cheann de na carachtair seo a leanas a bheith in ainmneacha fillteán:%n%n%1
DirExistsTitle=Tá an Fillteán Ann
DirExists=Tá an fillteán:%n%n%1%n%nann cheana féin. An bhfuil fonn ort suiteáil san fhillteán sin mar sin féin?
DirDoesntExistTitle=Níl an Fillteán Ann
DirDoesntExist=Níl an fillteán:%n%n%1%n%nann. An bhfuil fonn ort an fillteán a chruthú?

; *** "Select Components" wizard page
WizardSelectComponents=Roghnaigh Comhpháirteanna
SelectComponentsDesc=Cé na comhpháirteanna ba cheart a shuiteáil?
SelectComponentsLabel2=Roghnaigh na comhpháirteanna is mian leat a shuiteáil; glan na comhpháirteanna nach mian leat a shuiteáil. Cliceáil Ar Aghaidh nuair atá tú réidh chun leanúint ar aghaidh.
FullInstallation=Suiteáil iomlán
; if possible don't translate 'Compact' as 'Minimal' (I mean 'Minimal' in your language)
CompactInstallation=Suiteáil dhlúth
CustomInstallation=Suiteáil shaincheaptha
NoUninstallWarningTitle=Tá Comhpháirteanna Ann
NoUninstallWarning=Bhraith an tSuiteáil go bhfuil na comhpháirteanna seo a leanas suiteáilte ar do ríomhaire cheana féin:%n%n%1%n%nNí dhíshuiteálfar iad má dhíroghnaíonn tú iad.%n%nAn bhfuil fonn ort leanúint ar aghaidh mar sin féin?
ComponentSize1=%1 KB
ComponentSize2=%1 MB
ComponentsDiskSpaceGBLabel=Teastaíonn [gb] GB ar a laghad de spás diosca don rogha reatha.
ComponentsDiskSpaceMBLabel=Teastaíonn [mb] MB ar a laghad de spás diosca don rogha reatha.

; *** "Select Additional Tasks" wizard page
WizardSelectTasks=Roghnaigh Tascanna Breise
SelectTasksDesc=Cé na tascanna breise ba cheart a dhéanamh?
SelectTasksLabel2=Roghnaigh na tascanna breise is mian leat go ndéanfadh an tSuiteáil agus [name] á shuiteáil, ansin cliceáil Ar Aghaidh.

; *** "Select Start Menu Folder" wizard page
WizardSelectProgramGroup=Roghnaigh Fillteán sa Roghchlár Tosaigh
SelectStartMenuFolderDesc=Cá gcuirfidh an tSuiteáil aicearraí an chláir?
SelectStartMenuFolderLabel3=Cruthóidh an tSuiteáil aicearraí an chláir san fhillteán seo a leanas sa roghchlár Tosaigh.
SelectStartMenuFolderBrowseLabel=Chun leanúint ar aghaidh, cliceáil Ar Aghaidh. Más mian leat fillteán eile a roghnú, cliceáil Brabhsáil.
MustEnterGroupName=Caithfidh tú ainm fillteáin a iontráil.
GroupNameTooLong=Tá ainm an fhillteáin nó an chonair rófhada.
InvalidGroupName=Níl ainm an fhillteáin bailí.
BadGroupName=Ní féidir aon cheann de na carachtair seo a leanas a bheith in ainm an fhillteáin:%n%n%1
NoProgramGroupCheck2=&Ná cruthaigh fillteán sa roghchlár Tosaigh

; *** "Ready to Install" wizard page
WizardReady=Réidh le Suiteáil
ReadyLabel1=Tá an tSuiteáil réidh anois chun tosú ar [name] a shuiteáil ar do ríomhaire.
ReadyLabel2a=Cliceáil Suiteáil chun leanúint ar aghaidh leis an tsuiteáil, nó cliceáil Siar más mian leat socruithe a athbhreithniú nó a athrú.
ReadyLabel2b=Cliceáil Suiteáil chun leanúint ar aghaidh leis an tsuiteáil.
ReadyMemoUserInfo=Eolas úsáideora:
ReadyMemoDir=Suíomh sprice:
ReadyMemoType=Cineál suiteála:
ReadyMemoComponents=Comhpháirteanna roghnaithe:
ReadyMemoGroup=Fillteán sa roghchlár Tosaigh:
ReadyMemoTasks=Tascanna breise:

; *** TDownloadWizardPage wizard page and DownloadTemporaryFile
DownloadingLabel2=Comhaid á n-íoslódáil...
ButtonStopDownload=&Stop an íoslódáil
StopDownload=An bhfuil tú cinnte gur mian leat an íoslódáil a stopadh?
ErrorDownloadAborted=Tobscoireadh an íoslódáil
ErrorDownloadFailed=Theip ar an íoslódáil: %1 %2
ErrorDownloadSizeFailed=Theip ar an méid a fháil: %1 %2
ErrorProgress=Dul chun cinn neamhbhailí: %1 as %2
ErrorFileSize=Méid comhaid neamhbhailí: bhíothas ag súil le %1, aimsíodh %2

; *** TExtractionWizardPage wizard page and ExtractArchive
ExtractingLabel=Comhaid á n-asbhaint...
ButtonStopExtraction=&Stop an asbhaint
StopExtraction=An bhfuil tú cinnte gur mian leat an asbhaint a stopadh?
ErrorExtractionAborted=Tobscoireadh an asbhaint
ErrorExtractionFailed=Theip ar an asbhaint: %1

; *** Archive extraction failure details
ArchiveIncorrectPassword=Tá an pasfhocal mícheart
ArchiveIsCorrupted=Tá an chartlann truaillithe
ArchiveUnsupportedFormat=Ní thacaítear le formáid na cartlainne

; *** "Preparing to Install" wizard page
WizardPreparing=Ag Ullmhú le Suiteáil
PreparingDesc=Tá an tSuiteáil ag ullmhú chun [name] a shuiteáil ar do ríomhaire.
PreviousInstallNotCompleted=Níor críochnaíodh suiteáil nó baint cláir roimhe seo. Beidh ort do ríomhaire a atosú chun an tsuiteáil sin a chríochnú.%n%nTar éis duit do ríomhaire a atosú, rith an tSuiteáil arís chun suiteáil [name] a chríochnú.
CannotContinue=Ní féidir leis an tSuiteáil leanúint ar aghaidh. Cliceáil Cealaigh chun scor.
ApplicationsFound=Tá na feidhmchláir seo a leanas ag úsáid comhad a gcaithfidh an tSuiteáil iad a nuashonrú. Moltar duit ligean don tSuiteáil na feidhmchláir seo a dhúnadh go huathoibríoch.
ApplicationsFound2=Tá na feidhmchláir seo a leanas ag úsáid comhad a gcaithfidh an tSuiteáil iad a nuashonrú. Moltar duit ligean don tSuiteáil na feidhmchláir seo a dhúnadh go huathoibríoch. Nuair a bheidh an tsuiteáil críochnaithe, déanfaidh an tSuiteáil iarracht na feidhmchláir a atosú.
CloseApplications=Dún na feidhmchláir go h&uathoibríoch
DontCloseApplications=&Ná dún na feidhmchláir
ErrorCloseApplications=Níorbh fhéidir leis an tSuiteáil gach feidhmchlár a dhúnadh go huathoibríoch. Moltar duit gach feidhmchlár atá ag úsáid comhad a gcaithfidh an tSuiteáil iad a nuashonrú a dhúnadh sula leanann tú ar aghaidh.
PrepareToInstallNeedsRestart=Caithfidh an tSuiteáil do ríomhaire a atosú. Tar éis duit do ríomhaire a atosú, rith an tSuiteáil arís chun suiteáil [name] a chríochnú.%n%nAn bhfuil fonn ort atosú anois?

; *** "Installing" wizard page
WizardInstalling=Á Suiteáil
InstallingLabel=Fan go fóill, le do thoil, fad atá an tSuiteáil ag suiteáil [name] ar do ríomhaire.

; *** "Setup Completed" wizard page
FinishedHeadingLabel=Draoi Suiteála [name] á Chríochnú
FinishedLabelNoIcons=Tá [name] suiteáilte ag an tSuiteáil ar do ríomhaire.
FinishedLabel=Tá [name] suiteáilte ag an tSuiteáil ar do ríomhaire. Is féidir an feidhmchlár a thosú trí na haicearraí suiteáilte a roghnú.
ClickFinish=Cliceáil Críochnaigh chun scor den tSuiteáil.
FinishedRestartLabel=Chun suiteáil [name] a chríochnú, caithfidh an tSuiteáil do ríomhaire a atosú. An bhfuil fonn ort atosú anois?
FinishedRestartMessage=Chun suiteáil [name] a chríochnú, caithfidh an tSuiteáil do ríomhaire a atosú.%n%nAn bhfuil fonn ort atosú anois?
ShowReadmeCheck=Tá, ba mhaith liom an comhad README a fheiceáil
YesRadio=&Tá, atosaigh an ríomhaire anois
NoRadio=&Níl, atosóidh mé an ríomhaire ar ball
; used for example as 'Run MyProg.exe'
RunEntryExec=Rith %1
; used for example as 'View Readme.txt'
RunEntryShellExec=Féach ar %1

; *** "Setup Needs the Next Disk" stuff
ChangeDiskTitle=Teastaíonn an Chéad Diosca Eile ón tSuiteáil
SelectDiskLabel2=Cuir isteach Diosca %1 agus cliceáil OK.%n%nMás féidir na comhaid ar an diosca seo a aimsiú i bhfillteán seachas an ceann a thaispeántar thíos, iontráil an chonair cheart nó cliceáil Brabhsáil.
PathLabel=&Conair:
FileNotInDir2=Níorbh fhéidir an comhad "%1" a aimsiú i "%2". Cuir isteach an diosca ceart nó roghnaigh fillteán eile.
SelectDirectoryLabel=Sonraigh suíomh an chéad diosca eile.

; *** Installation phase messages
SetupAborted=Níor críochnaíodh an tSuiteáil.%n%nCeartaigh an fhadhb agus rith an tSuiteáil arís.
AbortRetryIgnoreSelectAction=Roghnaigh gníomh
AbortRetryIgnoreRetry=&Bain triail eile as
AbortRetryIgnoreIgnore=&Déan neamhaird den earráid agus lean ar aghaidh
AbortRetryIgnoreCancel=Cealaigh an tsuiteáil
RetryCancelSelectAction=Roghnaigh gníomh
RetryCancelRetry=&Bain triail eile as
RetryCancelCancel=Cealaigh

; *** Installation status messages
StatusClosingApplications=Feidhmchláir á ndúnadh...
StatusCreateDirs=Fillteáin á gcruthú...
StatusExtractFiles=Comhaid á n-asbhaint...
StatusDownloadFiles=Comhaid á n-íoslódáil...
StatusCreateIcons=Aicearraí á gcruthú...
StatusCreateIniEntries=Iontrálacha INI á gcruthú...
StatusCreateRegistryEntries=Iontrálacha clárlainne á gcruthú...
StatusRegisterFiles=Comhaid á gclárú...
StatusSavingUninstall=Eolas díshuiteála á shábháil...
StatusRunProgram=An tsuiteáil á críochnú...
StatusRestartingApplications=Feidhmchláir á n-atosú...
StatusRollback=Athruithe á rolladh siar...

; *** Misc. errors
ErrorInternal2=Earráid inmheánach: %1
ErrorFunctionFailedNoCode=Theip ar %1
ErrorFunctionFailed=Theip ar %1; cód %2
ErrorFunctionFailedWithMessage=Theip ar %1; cód %2.%n%3
ErrorExecutingProgram=Ní féidir an comhad a rith:%n%1

; *** Registry errors
ErrorRegOpenKey=Earráid le linn eochair chlárlainne a oscailt:%n%1\%2
ErrorRegCreateKey=Earráid le linn eochair chlárlainne a chruthú:%n%1\%2
ErrorRegWriteKey=Earráid le linn scríobh chuig eochair chlárlainne:%n%1\%2

; *** INI errors
ErrorIniEntry=Earráid le linn iontráil INI a chruthú sa chomhad "%1".

; *** File copying errors
FileAbortRetryIgnoreSkipNotRecommended=&Léim thar an gcomhad seo (ní mholtar)
FileAbortRetryIgnoreIgnoreNotRecommended=&Déan neamhaird den earráid agus lean ar aghaidh (ní mholtar)
SourceIsCorrupted=Tá an comhad foinse truaillithe
SourceDoesntExist=Níl an comhad foinse "%1" ann
SourceVerificationFailed=Theip ar fhíorú an chomhaid foinse: %1
VerificationSignatureDoesntExist=Níl an comhad sínithe "%1" ann
VerificationSignatureInvalid=Tá an comhad sínithe "%1" neamhbhailí
VerificationKeyNotFound=Úsáideann an comhad sínithe "%1" eochair anaithnid
VerificationFileNameIncorrect=Tá ainm an chomhaid mícheart
VerificationFileTagIncorrect=Tá clib an chomhaid mícheart
VerificationFileSizeIncorrect=Tá méid an chomhaid mícheart
VerificationFileHashIncorrect=Tá hais an chomhaid mícheart
ExistingFileReadOnly2=Níorbh fhéidir an comhad atá ann cheana a athsholáthar mar go bhfuil sé marcáilte mar inléite amháin.
ExistingFileReadOnlyRetry=&Bain an tréith inléite amháin agus bain triail eile as
ExistingFileReadOnlyKeepExisting=&Coinnigh an comhad atá ann cheana
ErrorReadingExistingDest=Tharla earráid agus iarracht á déanamh an comhad atá ann cheana a léamh:
FileExistsSelectAction=Roghnaigh gníomh
FileExists2=Tá an comhad ann cheana féin.
FileExistsOverwriteExisting=&Forscríobh an comhad atá ann cheana
FileExistsKeepExisting=&Coinnigh an comhad atá ann cheana
FileExistsOverwriteOrKeepAll=&Déan é seo do na coinbhleachtaí eile
ExistingFileNewerSelectAction=Roghnaigh gníomh
ExistingFileNewer2=Tá an comhad atá ann cheana níos nuaí ná an ceann atá an tSuiteáil ag iarraidh a shuiteáil.
ExistingFileNewerOverwriteExisting=&Forscríobh an comhad atá ann cheana
ExistingFileNewerKeepExisting=&Coinnigh an comhad atá ann cheana (molta)
ExistingFileNewerOverwriteOrKeepAll=&Déan é seo do na coinbhleachtaí eile
ErrorChangingAttr=Tharla earráid agus iarracht á déanamh tréithe an chomhaid atá ann cheana a athrú:
ErrorCreatingTemp=Tharla earráid agus iarracht á déanamh comhad a chruthú san fhillteán sprice:
ErrorReadingSource=Tharla earráid agus iarracht á déanamh an comhad foinse a léamh:
ErrorCopying=Tharla earráid agus iarracht á déanamh comhad a chóipeáil:
ErrorDownloading=Tharla earráid agus iarracht á déanamh comhad a íoslódáil:
ErrorExtracting=Tharla earráid agus iarracht á déanamh cartlann a asbhaint:
ErrorReplacingExistingFile=Tharla earráid agus iarracht á déanamh an comhad atá ann cheana a athsholáthar:
ErrorRestartReplace=Theip ar RestartReplace:
ErrorRenamingTemp=Tharla earráid agus iarracht á déanamh comhad a athainmniú san fhillteán sprice:
ErrorRegisterServer=Ní féidir an DLL/OCX a chlárú: %1
ErrorRegSvr32Failed=Theip ar RegSvr32 le cód scoir %1
ErrorRegisterTypeLib=Ní féidir an leabharlann cineálacha a chlárú: %1

; *** Uninstall display name markings
; used for example as 'My Program (32-bit)'
UninstallDisplayNameMark=%1 (%2)
; used for example as 'My Program (32-bit, All users)'
UninstallDisplayNameMarks=%1 (%2, %3)
UninstallDisplayNameMark32Bit=32 giotán
UninstallDisplayNameMark64Bit=64 giotán
UninstallDisplayNameMarkAllUsers=Gach úsáideoir
UninstallDisplayNameMarkCurrentUser=An t-úsáideoir reatha

; *** Post-installation errors
ErrorOpeningReadme=Tharla earráid agus iarracht á déanamh an comhad README a oscailt.
ErrorRestartingComputer=Níorbh fhéidir leis an tSuiteáil an ríomhaire a atosú. Déan é seo de láimh.

; *** Uninstaller messages
UninstallNotFound=Níl an comhad "%1" ann. Ní féidir díshuiteáil.
UninstallOpenError=Níorbh fhéidir an comhad "%1" a oscailt. Ní féidir díshuiteáil
UninstallUnsupportedVer=Tá an logchomhad díshuiteála "%1" i bhformáid nach n-aithníonn an leagan seo den díshuiteálaí. Ní féidir díshuiteáil
UninstallUnknownEntry=Thángthas ar iontráil anaithnid (%1) sa logchomhad díshuiteála
ConfirmUninstall=An bhfuil tú cinnte gur mian leat %1 agus a chomhpháirteanna go léir a bhaint go hiomlán?
UninstallOnlyOnWin64=Ní féidir an tsuiteáil seo a dhíshuiteáil ach ar Windows 64 giotán.
OnlyAdminCanUninstall=Ní féidir an tsuiteáil seo a dhíshuiteáil ach ag úsáideoir a bhfuil pribhléidí riaracháin aige.
UninstallStatusLabel=Fan go fóill, le do thoil, fad atá %1 á bhaint de do ríomhaire.
UninstalledAll=Baineadh %1 de do ríomhaire go rathúil.
UninstalledMost=Tá díshuiteáil %1 críochnaithe.%n%nNíorbh fhéidir roinnt eilimintí a bhaint. Is féidir iad a bhaint de láimh.
UninstalledAndNeedsRestart=Chun díshuiteáil %1 a chríochnú, caithfear do ríomhaire a atosú.%n%nAn bhfuil fonn ort atosú anois?
UninstallDataCorrupted=Tá an comhad "%1" truaillithe. Ní féidir díshuiteáil

; *** Uninstallation phase messages
ConfirmDeleteSharedFileTitle=Bain an Comhad Comhroinnte?
ConfirmDeleteSharedFile2=Léiríonn an córas nach bhfuil aon chlár ag úsáid an chomhaid chomhroinnte seo a leanas a thuilleadh. An mian leat go mbainfeadh an Díshuiteáil an comhad comhroinnte seo?%n%nMá tá cláir fós ag úsáid an chomhaid seo agus má bhaintear é, seans nach n-oibreoidh na cláir sin i gceart. Mura bhfuil tú cinnte, roghnaigh Níl. Ní dhéanfaidh sé aon dochar an comhad a fhágáil ar do chóras.
SharedFileNameLabel=Ainm an chomhaid:
SharedFileLocationLabel=Suíomh:
WizardUninstalling=Stádas Díshuiteála
StatusUninstalling=%1 á dhíshuiteáil...

; *** Shutdown block reasons
ShutdownBlockReasonInstallingApp=%1 á shuiteáil.
ShutdownBlockReasonUninstallingApp=%1 á dhíshuiteáil.

; The custom messages below aren't used by Setup itself, but if you make
; use of them in your scripts, you'll want to translate them.

[CustomMessages]

NameAndVersion=%1 leagan %2
AdditionalIcons=Aicearraí breise:
CreateDesktopIcon=Cruthaigh aicearra ar an &deasc
CreateQuickLaunchIcon=Cruthaigh aicearra &Mearthosaithe
ProgramOnTheWeb=%1 ar an nGréasán
UninstallProgram=Díshuiteáil %1
LaunchProgram=Seol %1
AssocFileExtension=&Comhcheangail %1 leis an iarmhír chomhaid %2
AssocingFileExtension=%1 á chomhcheangal leis an iarmhír chomhaid %2...
AutoStartProgramGroupDescription=Tosú:
AutoStartProgram=Tosaigh %1 go huathoibríoch
AddonHostProgramNotFound=Níorbh fhéidir %1 a aimsiú san fhillteán a roghnaigh tú.%n%nAn bhfuil fonn ort leanúint ar aghaidh mar sin féin?
