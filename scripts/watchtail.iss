; Inno Setup script for Watchtail (Windows installer).
;
; Build the portable bundle first:
;     scripts\build_all.sh zip        (or run pyinstaller manually)
; Then compile this script with Inno Setup 6+ (ISCC.exe watchtail.iss).
; The installer is written to dist\output\watchtail-setup-<version>.exe.

#define AppName "Watchtail"
#define AppVersion GetVersionCode
#define AppPublisher "Watchtail project"
#define AppExe "watchtail.exe"

[Setup]
AppId={{7C1F2C2E-6C4A-4E2A-9B5D-WATCHTAIL000}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\Watchtail
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
LicenseFile=LICENSE
OutputDir=dist\output
OutputBaseFilename=watchtail-setup-{#AppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
UninstallDisplayIcon={app}\{#AppExe}

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; \
    GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "build\dist\watchtail\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{group}\{#AppName} (server logs)"; Filename: "{app}\data"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchProgram,{#AppName}}"; \
    Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Remove generated runtime data with the program (opt-out by saving the folder).
Type: filesandordirs; Name: "{app}\data"

[Code]
function GetVersionCode: String;
begin
  { Keep in sync with pyproject.toml; parsed by scripts/release.sh when staging. }
  Result := '0.2.0';
end;
