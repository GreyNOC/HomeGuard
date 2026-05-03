#define AppVersion GetEnv("HOMEGUARD_RELEASE_VERSION")
#define RepoRoot GetEnv("HOMEGUARD_REPO_ROOT")
#define AppSource RepoRoot + "\dist\electron\win-unpacked"
#define OutputDir RepoRoot + "\dist\installer"
#define OutputName "GreyNOC-HomeGuard-Setup-v" + AppVersion

[Setup]
AppId={{D7D9B048-17D6-48C0-BD91-78D5E19353BD}
AppName=GreyNOC HomeGuard
AppVersion={#AppVersion}
AppPublisher=GreyNOC
DefaultDirName={autopf}\GreyNOC HomeGuard
DefaultGroupName=GreyNOC HomeGuard
DisableProgramGroupPage=yes
LicenseFile={#RepoRoot}\LICENSE
OutputDir={#OutputDir}
OutputBaseFilename={#OutputName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayName=GreyNOC HomeGuard
VersionInfoCompany=GreyNOC
VersionInfoDescription=GreyNOC HomeGuard Setup
VersionInfoProductName=GreyNOC HomeGuard
VersionInfoProductVersion={#AppVersion}
VersionInfoVersion={#AppVersion}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
Source: "{#AppSource}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\GreyNOC HomeGuard"; Filename: "{app}\GreyNOC-HomeGuard.exe"
Name: "{commondesktop}\GreyNOC HomeGuard"; Filename: "{app}\GreyNOC-HomeGuard.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\GreyNOC-HomeGuard.exe"; Description: "Launch GreyNOC HomeGuard"; Flags: nowait postinstall skipifsilent
