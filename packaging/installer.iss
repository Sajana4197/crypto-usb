; Inno Setup script for A Cryptographic Security Layer for USB Storage.
;
; Requires Inno Setup (https://jrsoftware.org/isinfo.php) — a separate
; Windows application, not installable via pip, so it is not run as part
; of this repository's automated build/test process. Build the
; PyInstaller output first (see packaging/crypto_usb.spec), then compile
; this script with Inno Setup's `iscc.exe`:
;
;   pyinstaller packaging/crypto_usb.spec --distpath dist --workpath build
;   iscc packaging/installer.iss
;
; Output: packaging/Output/CryptoUSB-Setup.exe

#define MyAppName "Cryptographic Security Layer for USB Storage"
#define MyAppShortName "CryptoUSB"
#define MyAppVersion "0.1.0"
#define MyAppPublisher "CryptoUSB Research Project"
#define MyAppExeName "CryptoUSB.exe"

[Setup]
AppId={{B3E1B6B4-6C7A-4B7E-9F1D-4E5C9A9C7B10}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppShortName}
DefaultGroupName={#MyAppShortName}
DisableProgramGroupPage=yes
; Each user gets their own account database, config, and logs (see
; utils/paths.py — all three live next to the executable) — installing
; per-machine under Program Files is fine since Windows grants write
; access to a per-user AppData-relocated install, but for the simplest,
; most demo-friendly behavior this defaults to a per-user install
; directory instead, so no elevation is required and every user's data
; naturally stays private to them.
PrivilegesRequired=lowest
DefaultDirName={autopf}\{#MyAppShortName}
OutputDir=Output
OutputBaseFilename=CryptoUSB-Setup
Compression=lzma
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\{#MyAppExeName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; The entire PyInstaller onedir output — CryptoUSB.exe plus its
; bundled _internal/ (PySide6, cryptography, resources/, etc.).
Source: "..\dist\CryptoUSB\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:UninstallProgram,{#MyAppShortName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppShortName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppShortName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Remove the per-installation SQLite database, config, and logs on
; uninstall. This deliberately does NOT ask "keep your data?" the way
; some installers do — a security-focused demonstration tool being
; uninstalled should not silently leave an account database and access
; log behind. Users who want to keep them should back up `data/` and
; `logs/` from the install directory first.
Type: filesandordirs; Name: "{app}\data"
Type: filesandordirs; Name: "{app}\logs"
