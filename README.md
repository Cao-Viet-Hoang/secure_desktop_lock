# SecureDesktopLock

A production-ready Windows desktop lock application built with C# / WPF (.NET Framework 4.7.2).

It presents a fullscreen overlay window after Windows login, blocks system keyboard shortcuts, validates a password stored in Firebase Realtime Database (per-machine), and rotates the password after every successful unlock.

> **The application does NOT modify the Windows login password.** It is a desktop overlay only.

---

## Table of Contents

1. [Architecture](#architecture)
2. [Prerequisites](#prerequisites)
3. [Firebase Setup](#firebase-setup)
4. [Build & Publish](#build--publish)
5. [Deployment](#deployment)
6. [Realtime Database Security Rules](#realtime-database-security-rules)
7. [Offline Mode](#offline-mode)
8. [Watchdog & Self-Recovery](#watchdog--self-recovery)
9. [Password Rotation](#password-rotation)
10. [Security Notes](#security-notes)
11. [File Structure](#file-structure)

---

## Architecture

```
SecureDesktopLock/
├── App.xaml / App.xaml.cs          ← Startup, single-instance mutex, watchdog, autostart
├── Models/
│   └── MachineInfo.cs              ← Reads Windows Machine GUID from registry
├── Services/
│   ├── EncryptionService.cs        ← DPAPI (ProtectedData.CurrentUser) encrypt/decrypt
│   ├── FirebaseService.cs          ← Firebase Realtime Database via FireSharp library
│   ├── KeyboardHookService.cs      ← SetWindowsHookEx WH_KEYBOARD_LL to block system keys
│   └── PasswordRotationService.cs  ← CSPRNG password generation + upload + local cache
├── UI/
│   ├── LockWindow.xaml             ← Fullscreen borderless dark overlay
│   └── LockWindow.xaml.cs          ← Win32 hardening (removes SysMenu, enforces TOPMOST)
├── Utils/
│   ├── Converters.cs               ← BoolToVisibility, BoolNegation value converters
│   └── Logger.cs                   ← Daily rolling log file in %ProgramData%\SecureLock\Logs\
└── ViewModels/
    ├── LockViewModel.cs            ← MVVM: password validation, Firebase/cache fallback
    └── RelayCommand.cs             ← ICommand implementation
```

### Unlock flow

```
User types password → UnlockButton_Click
  → LockViewModel.UnlockCommand.Execute(SecurePassword)
      → FirebaseService.GetPasswordAsync(machineId)   ← online path
          OR PasswordRotationService.ReadCachedPassword()  ← offline fallback
      → EncryptionService.Decrypt(storedBlob)
      → Compare with entered password
      → SUCCESS → PasswordRotationService.RotateAsync() → new password in Firebase + cache
               → UnlockSucceeded event → LockWindow.Close() → Application.Shutdown()
      → FAILURE → increment attempt counter, log, show message
```

---

## Prerequisites

| Requirement      | Details                                        |
| ---------------- | ---------------------------------------------- |
| Windows          | 10 (1903+) or 11                               |
| .NET Framework   | 4.7.2 (pre-installed on Win10/11)              |
| Visual Studio    | 2019 or 2022 (Community edition is sufficient) |
| Firebase project | With Realtime Database enabled                 |

---

## Firebase Setup

### 1 — Create a Firebase project

1. Go to [https://console.firebase.google.com](https://console.firebase.google.com).
2. Click **Add project** → follow the wizard.
3. Under **Build** → **Realtime Database** → click **Create Database**.
4. Choose your database location (e.g. `asia-southeast1`).
5. Select **Start in locked mode** (you will add security rules in step 4).

### 2 — Get the Database Secret

1. In the Firebase console → ⚙️ **Project Settings** → **Service accounts** tab.
2. Scroll to **Database secrets** → click **Show** to reveal the secret.
3. Create a JSON config file on each target machine, e.g.:
   ```
   C:\ProgramData\SecureLock\firebase_config.json
   ```
4. With the following content:
   ```json
   {
     "base_path": "https://<project-id>-default-rtdb.<region>.firebasedatabase.app/",
     "auth_secret": "<your-database-secret>"
   }
   ```
5. Set NTFS permissions so only `SYSTEM` and the deploying admin account can read the file:
   ```bat
   icacls "C:\ProgramData\SecureLock\firebase_config.json" /inheritance:r
   icacls "C:\ProgramData\SecureLock\firebase_config.json" /grant "NT AUTHORITY\SYSTEM:(R)"
   icacls "C:\ProgramData\SecureLock\firebase_config.json" /grant "BUILTIN\Administrators:(R)"
   ```

### 3 — Configure App.config

Open `SecureDesktopLock\App.config` and set the path:

```xml
<add key="FirebaseConfigPath"
     value="C:\ProgramData\SecureLock\firebase_config.json" />
```

### 4 — Seed the initial password

Before deploying, create the initial data node for each machine.

The `current_password` field contains the password in **plain text**.

#### Via Firebase console

1. Go to **Realtime Database** in the Firebase console.
2. Create a node `machines`.
3. Under `machines`, add a child node with the **Windows Machine GUID** as the key.
   - Get the GUID from the target machine: `reg query HKLM\SOFTWARE\Microsoft\Cryptography /v MachineGuid`
4. Add two child values:
   - `current_password` (string) → your initial password, e.g. `123456`
   - `last_updated` (string) → current GMT+7 timestamp, e.g. `2026-02-24T07:00:00+07:00`

---

## Build & Publish

### Debug build

```
Visual Studio → Build → Build Solution  (Ctrl+Shift+B)
```

### Release build + single-file publish

```bat
msbuild SecureDesktopLock.sln /p:Configuration=Release /p:Platform=AnyCPU
```

The output is in:

```
SecureDesktopLock\bin\Release\SecureDesktopLock.exe
```

### Recommended publish checklist

- [ ] `App.config` updated with correct `FirebaseConfigPath`
- [ ] Firebase config JSON (`firebase_config.json`) deployed to target machine
- [ ] Initial password seeded in Realtime Database
- [ ] Application signed with a code-signing certificate
- [ ] Antivirus exclusion added for `SecureDesktopLock.exe` (keyboard hook triggers heuristics)

---

## Deployment

### Option A — Registry Run key (default, no admin rights needed)

The application writes its own autostart entry at first launch:

```
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
  SecureDesktopLock = "C:\...\SecureDesktopLock.exe"
```

### Option B — Task Scheduler (recommended for managed environments)

Create a task that triggers on **At log on** of the target user:

```powershell
$action  = New-ScheduledTaskAction -Execute "C:\Program Files\SecureLock\SecureDesktopLock.exe"
$trigger = New-ScheduledTaskTrigger -AtLogOn -User "DOMAIN\TargetUser"
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit 0 -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName "SecureDesktopLock" -Action $action -Trigger $trigger -Settings $settings -RunLevel Highest
```

Using `-RestartCount 3` provides OS-level self-recovery on top of the in-process watchdog.

### Option C — Windows Service companion (strongest recovery)

Deploy a separate Windows Service that monitors the lock process and restarts it on termination. This survives even `taskkill /F` attacks. A reference implementation using `ServiceBase` is provided in `Tools/WatchdogService/`.

---

## Realtime Database Security Rules

Restrict Realtime Database access using security rules:

```json
{
  "rules": {
    "machines": {
      ".read": "auth != null",
      ".write": "auth != null"
    }
  }
}
```

With Database Secret authentication (used by FireSharp), requests are treated as admin and bypass rules. The rules above protect against unauthenticated REST access. Adjust if you add a management dashboard.

---

## Offline Mode

When Firebase is unreachable (no Internet, DNS failure, etc.) the application falls back to the locally cached password:

```
%ProgramData%\SecureLock\cache.dat
```

The cache contains the same password blob that was last successfully retrieved from Firebase Realtime Database. The cache is updated every time Firebase is successfully queried.

**Important:** Passwords are stored as **plain text** in Firebase Realtime Database and the local cache. If you later need encryption, implement it in `EncryptionService.cs` — all other code automatically goes through that service.

---

## Watchdog & Self-Recovery

Two layers of watchdog protection are included:

| Layer         | Mechanism                                                 | Survives                              |
| ------------- | --------------------------------------------------------- | ------------------------------------- |
| In-process    | Background thread checks `MainWindow.IsVisible` every 5 s | Window closed via code / exception    |
| OS-level      | Task Scheduler restart policy (`-RestartCount 3`)         | Process termination (`taskkill`)      |
| Service-level | Companion Windows Service (optional)                      | Any process kill, including `SIGKILL` |

---

## Password Rotation

After every successful unlock a new 6-digit cryptographically random password is generated (drawn from `RNGCryptoServiceProvider`) and uploaded to Firebase Realtime Database. The local cache is also updated atomically.

This means each unlock session consumes a unique one-time password, so replaying captured password attempts is ineffective.

---

## Logging

Log files are written to:

```
%ProgramData%\SecureLock\Logs\SecureLock_YYYY-MM-DD.log
```

Logged events:

- `UNLOCK_SUCCESS` — machine ID, timestamp
- `UNLOCK_FAILURE` — machine ID, attempt number
- `FIREBASE_ERROR` — full exception, context tag
- `INFO` / `WARN` / `ERROR` — general lifecycle events

---

## Security Notes

| Concern                           | Mitigation                                                                                   |
| --------------------------------- | -------------------------------------------------------------------------------------------- |
| Keyboard shortcuts (Alt+Tab etc.) | `SetWindowsHookEx(WH_KEYBOARD_LL)` blocks at OS level                                        |
| Window close                      | `Closing` event cancels; system menu removed via `SetWindowLong`                             |
| Multiple instances                | Named `Mutex` (Global namespace) at startup                                                  |
| Plain-text password in memory     | `SecureString` on input; zeroed after comparison                                             |
| Firebase credential exposure      | Config JSON restricted by NTFS ACL; never embedded in binary                                 |
| Password replay                   | Password rotated after every successful unlock                                               |
| Ctrl+Alt+Del                      | Cannot be fully blocked in user-mode; the SAS screen appears but returns to the lock overlay |
| Password storage                  | Currently **plaintext** — add encryption in `EncryptionService.cs` if required               |

---

## File Structure (Full)

```
SecureDesktopLock.sln
├── SecureDesktopLock/
│   ├── App.config
│   ├── App.xaml
│   ├── App.xaml.cs
│   ├── MainWindow.xaml          (kept for compatibility; not used at runtime)
│   ├── MainWindow.xaml.cs
│   ├── SecureDesktopLock.csproj
│   ├── Models/
│   │   └── MachineInfo.cs
│   ├── Services/
│   │   ├── EncryptionService.cs
│   │   ├── FirebaseService.cs
│   │   ├── KeyboardHookService.cs
│   │   └── PasswordRotationService.cs
│   ├── UI/
│   │   ├── LockWindow.xaml
│   │   └── LockWindow.xaml.cs
│   ├── Utils/
│   │   ├── Converters.cs
│   │   └── Logger.cs
│   ├── ViewModels/
│   │   ├── LockViewModel.cs
│   │   └── RelayCommand.cs
│   └── Properties/
│       ├── AssemblyInfo.cs
│       ├── Resources.resx
│       └── Settings.settings
├── firebase_config.example.json            ← template only, never fill in real secrets
├── .gitignore
└── README.md
```
