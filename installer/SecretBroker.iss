; SecretBroker setup program. Build it with tools\build_installer.ps1 (stages Python first).

#ifndef AppVersion
  #define AppVersion "0.9.0"
#endif
#define StageDir "..\build\stage"
#define AppIcon "{app}\python\Lib\site-packages\secretbroker\assets\icon.ico"

[Setup]
AppId={{6B0F2E8A-4C1D-4E7B-9A35-5D2C8F1E7A90}
AppName=SecretBroker
AppVersion={#AppVersion}
AppVerName=SecretBroker {#AppVersion}
AppPublisher=CXIOME
DefaultDirName={autopf}\SecretBroker
DisableDirPage=yes
DisableProgramGroupPage=yes
DisableReadyPage=yes
DisableWelcomePage=no
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
OutputDir=..\dist
OutputBaseFilename=SecretBroker-Setup-{#AppVersion}
SetupIconFile=..\secretbroker\assets\icon.ico
UninstallDisplayIcon={#AppIcon}
UninstallDisplayName=SecretBroker
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
WizardSizePercent=100
CloseApplications=yes
RestartApplications=no
ChangesEnvironment=yes

[Languages]
Name: "es"; MessagesFile: "compiler:Languages\Spanish.isl"

[Messages]
es.WelcomeLabel2=Se instalará [name/ver] en este equipo.%n%nSecretBroker guarda tus contraseñas y API keys cifradas y deja que la IA las use sin poder leerlas. Funciona con una cuenta de Windows propia para que ningún otro programa pueda acceder a ellas.

[Tasks]
Name: "desktopicon"; Description: "Crear un acceso directo en el escritorio"

[InstallDelete]
; A clean runtime on every install or update, so no stale packages are left behind.
Type: filesandordirs; Name: "{app}\python"

[Files]
Source: "{#StageDir}\python\*"; DestDir: "{app}\python"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "common.ps1"; DestDir: "{app}\setup"; Flags: ignoreversion
Source: "configure.ps1"; DestDir: "{app}\setup"; Flags: ignoreversion
Source: "sb.cmd"; DestDir: "{app}\bin"; Flags: ignoreversion

[Registry]
; `sb` (sb run -- npm run dev) from any terminal.
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}\bin"; Check: NeedsAddPath(ExpandConstant('{app}\bin'))

[Icons]
Name: "{autoprograms}\SecretBroker"; Filename: "{app}\python\pythonw.exe"; Parameters: "-I -m secretbroker.app"; WorkingDir: "{app}"; IconFilename: "{#AppIcon}"; Comment: "Bóveda de credenciales para tu IA"
Name: "{autodesktop}\SecretBroker"; Filename: "{app}\python\pythonw.exe"; Parameters: "-I -m secretbroker.app"; WorkingDir: "{app}"; IconFilename: "{#AppIcon}"; Tasks: desktopicon

[Run]
Filename: "{app}\python\pythonw.exe"; Parameters: "-I -m secretbroker.app"; Description: "Abrir SecretBroker"; Flags: postinstall nowait skipifsilent runasoriginaluser
; Updates started from the app run silently: reopen it when they finish.
Filename: "{app}\python\pythonw.exe"; Parameters: "-I -m secretbroker.app"; Flags: nowait runasoriginaluser; Check: WizardSilent

[UninstallRun]
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\setup\configure.ps1"" -Uninstall"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveService"

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Code]
var
  OwnerName, OwnerAppData: String;
  RemoveVault: Boolean;

{ The setup runs elevated; the vault belongs to the person who started it. }
procedure ReadOriginalUser();
var
  OutFile: String;
  Lines: TArrayOfString;
  ResultCode: Integer;
begin
  OutFile := ExpandConstant('{%PUBLIC|C:\Users\Public}\secretbroker-setup-owner.txt');
  DeleteFile(OutFile);
  ExecAsOriginalUser(ExpandConstant('{cmd}'), '/c (whoami & echo %APPDATA%) > "' + OutFile + '"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  if LoadStringsFromFile(OutFile, Lines) and (GetArrayLength(Lines) >= 2) then
  begin
    OwnerName := Trim(Lines[0]);
    OwnerAppData := Trim(Lines[1]);
  end;
  DeleteFile(OutFile);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  ReadOriginalUser();
  if OwnerName = '' then
  begin
    Result := 'No se pudo identificar al usuario que ejecuta la instalación.';
    exit;
  end;
  { Stop a running service and app so their files can be replaced. }
  Exec('schtasks.exe', '/End /TN "SecretBroker Service"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('powershell.exe', '-NoProfile -Command "Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -like ''' +
       ExpandConstant('{app}') + '\*'' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Result := '';
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
begin
  if CurStep <> ssPostInstall then
    exit;
  WizardForm.StatusLabel.Caption := 'Configurando el servicio protegido…';
  WizardForm.ProgressGauge.Style := npbstMarquee;
  Exec('powershell.exe', '-NoProfile -ExecutionPolicy Bypass -File "' + ExpandConstant('{app}\setup\configure.ps1') +
       '" -Owner "' + OwnerName + '" -OwnerAppData "' + OwnerAppData + '"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  WizardForm.ProgressGauge.Style := npbstNormal;
  if ResultCode <> 0 then
  begin
    MsgBox('No se pudo configurar el servicio de SecretBroker.' + #13#10 + 'Detalles: ' +
           ExpandConstant('{app}\setup\configure.log'), mbError, MB_OK);
    exit;
  end;
  { Connect Claude Code / Claude Desktop for the desktop user, if they are installed. }
  WizardForm.StatusLabel.Caption := 'Conectando con Claude…';
  ExecAsOriginalUser(ExpandConstant('{app}\python\python.exe'),
       '-I -c "from secretbroker import integrations; integrations.auto_connect()"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

function NeedsAddPath(Dir: String): Boolean;
var
  Path: String;
begin
  if not RegQueryStringValue(HKLM, 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'Path', Path) then
  begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Path) + ';') = 0;
end;

procedure RemoveFromPath(Dir: String);
var
  Path: String;
  P: Integer;
begin
  if not RegQueryStringValue(HKLM, 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'Path', Path) then
    exit;
  P := Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Path) + ';');
  if P = 0 then
    exit;
  if P = 1 then
    Delete(Path, 1, Length(Dir) + 1)
  else
    Delete(Path, P - 1, Length(Dir) + 1);
  RegWriteExpandStringValue(HKLM, 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'Path', Path);
end;

{ [UninstallRun] removes the service first; the vault is only deleted afterwards, and only if asked.
  Silent uninstalls keep it. }
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataRoot: String;
begin
  DataRoot := ExpandConstant('{commonappdata}\SecretBroker');
  if (CurUninstallStep = usUninstall) and DirExists(DataRoot + '\data') then
    RemoveVault := SuppressibleMsgBox('¿Borrar también la bóveda con todas tus credenciales?' + #13#10#13#10 +
      'Si eliges «Sí», se perderán definitivamente y no se podrán recuperar.' + #13#10 +
      'Si eliges «No», se conservan en ' + DataRoot + ' y volverán a estar disponibles si reinstalas SecretBroker.',
      mbConfirmation, MB_YESNO or MB_DEFBUTTON2, IDNO) = IDYES;
  if CurUninstallStep = usUninstall then
    RemoveFromPath(ExpandConstant('{app}\bin'));
  if (CurUninstallStep = usPostUninstall) and RemoveVault then
    if not DelTree(DataRoot, True, True, True) then
      SuppressibleMsgBox('No se pudo borrar por completo ' + DataRoot + '. Puedes eliminar la carpeta a mano.', mbError, MB_OK, IDOK);
end;
