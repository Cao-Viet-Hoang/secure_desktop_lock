using Microsoft.Win32;
using SecureDesktopLock.Models;
using SecureDesktopLock.Services;
using SecureDesktopLock.UI;
using SecureDesktopLock.Utils;
using SecureDesktopLock.ViewModels;
using System;
using System.Diagnostics;
using System.Reflection;
using System.Threading;
using System.Windows;

namespace SecureDesktopLock
{
    /// <summary>
    /// Application entry point.
    ///
    /// Startup sequence
    /// ----------------
    ///   1. Acquire a named Mutex — if one already exists, exit immediately
    ///      (single-instance enforcement).
    ///   2. Register the executable for auto-start via the HKCU Run registry
    ///      key so the lock is re-applied after the next Windows login.
    ///   3. Start the watchdog: a background thread that monitors the current
    ///      process and re-launches it if an external actor terminates it.
    ///   4. Initialise services (Encryption, Firebase, Rotation).
    ///   5. Auto-seed Firebase with an initial password if none exists (fire-and-forget).
    ///   6. Install the low-level keyboard hook.
    ///   7. Create and display the fullscreen LockWindow.
    ///
    /// Shutdown sequence
    /// -----------------
    ///   On Application_Exit the keyboard hook is unhooked and the Mutex is
    ///   released so a future restart can acquire it.
    /// </summary>
    public partial class App : Application
    {
        // ------------------------------------------------------------------ //
        //  Single-instance mutex name (must be globally unique)              //
        // ------------------------------------------------------------------ //
        private const string MutexName = "Global\\SecureDesktopLock_SingleInstance_7E3A9B1C";

        // ------------------------------------------------------------------ //
        //  Registry autostart                                                //
        // ------------------------------------------------------------------ //
        private const string RunKeyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
        private const string RunKeyName = "SecureDesktopLock";

        // ------------------------------------------------------------------ //
        //  Fields                                                             //
        // ------------------------------------------------------------------ //
        private Mutex _singleInstanceMutex;
        private KeyboardHookService _keyboardHook;
        private FirebaseService _firebaseService;
        private EncryptionService _encryptionService;
        private PasswordRotationService _rotationService;

        // Watchdog thread
        private Thread _watchdogThread;
        private bool _appExiting = false;

        // Active lock window (null when screen is unlocked)
        private LockWindow _activeLockWindow;

        // ------------------------------------------------------------------ //
        //  Application_Startup                                               //
        // ------------------------------------------------------------------ //

        private void Application_Startup(object sender, StartupEventArgs e)
        {
            Logger.LogInfo("Application starting.");

            // ── 1. Single-instance guard ──────────────────────────────────
            _singleInstanceMutex = new Mutex(
                initiallyOwned: true,
                name: MutexName,
                out bool createdNew);

            if (!createdNew)
            {
                // Another instance is already running — bring it to foreground
                // (best-effort) and exit this duplicate process.
                Logger.LogInfo("Duplicate instance detected — exiting.");
                _singleInstanceMutex.Dispose();
                Shutdown(0);
                return;
            }

            // ── 2. Auto-start registration ────────────────────────────────
            RegisterAutoStart();

            // ── 3. Watchdog ───────────────────────────────────────────────
            StartWatchdog();

            // ── 4. Service initialisation ─────────────────────────────────
            _encryptionService = new EncryptionService();

            try
            {
                _firebaseService = FirebaseService.CreateFromConfigFile();
                Logger.LogInfo(
                    $"Firebase service initialised. Config path: " +
                    $"{System.Configuration.ConfigurationManager.AppSettings["FirebaseConfigPath"]}");
            }
            catch (Exception ex)
            {
                // Firebase config missing or invalid — log and continue in
                // offline-only mode.  The lock screen will use cached data.
                Logger.LogFirebaseError(ex, "App.Startup.FirebaseInit");
                Logger.LogError(
                    $"Firebase config path was: " +
                    $"{System.Configuration.ConfigurationManager.AppSettings["FirebaseConfigPath"] ?? "(null)"}");
                _firebaseService = null;
            }

            FirebaseService fs = _firebaseService
                ?? new NullFirebaseService();

            _rotationService = new PasswordRotationService(fs, _encryptionService);

            // ── 5. Auto-seed password (fire-and-forget) ───────────────────
            // If this machine has no password record in Firebase yet, generate
            // one and upload it automatically.  Runs in the background so the
            // lock window appears immediately without waiting for the network.
            {
                string machineId = MachineInfo.GetMachineId();
                _ = _rotationService.EnsurePasswordExistsAsync(machineId);
            }

            // ── 6. Keyboard hook ──────────────────────────────────────────
            _keyboardHook = new KeyboardHookService();
            _keyboardHook.Start();

            // ── 7. Power / session event hooks ───────────────────────────
            // Resume from sleep/hibernate → re-lock immediately.
            SystemEvents.PowerModeChanged += OnPowerModeChanged;
            // Windows session unlock (Win+L then re-login) → re-lock.
            SystemEvents.SessionSwitch += OnSessionSwitch;

            // ── 8. Show lock window ───────────────────────────────────────
            ShowLockWindow();
        }

        // ------------------------------------------------------------------ //
        //  Application_Exit                                                  //
        // ------------------------------------------------------------------ //

        private void Application_Exit(object sender, ExitEventArgs e)
        {
            _appExiting = true;

            // Unsubscribe power / session events
            SystemEvents.PowerModeChanged -= OnPowerModeChanged;
            SystemEvents.SessionSwitch -= OnSessionSwitch;

            _keyboardHook?.Stop();
            _keyboardHook?.Dispose();

            _firebaseService?.Dispose();

            try
            {
                _singleInstanceMutex?.ReleaseMutex();
                _singleInstanceMutex?.Dispose();
            }
            catch (ApplicationException)
            {
                // Mutex was already released — ignore
            }

            Logger.LogInfo("Application exited.");
        }

        // ------------------------------------------------------------------ //
        //  Lock window                                                       //
        // ------------------------------------------------------------------ //

        private void ShowLockWindow()
        {
            // Guard: never open a second lock window while one is already visible.
            if (_activeLockWindow != null && _activeLockWindow.IsVisible)
            {
                _activeLockWindow.Activate();
                return;
            }

            FirebaseService fs = _firebaseService
                ?? new NullFirebaseService();

            LockViewModel viewModel = new LockViewModel(
                fs,
                _encryptionService,
                _rotationService);

            LockWindow lockWindow = new LockWindow();
            lockWindow.SetViewModel(viewModel);
            _activeLockWindow = lockWindow;

            // After a successful unlock the window closes.
            // Stay resident so sleep/resume events can re-lock the screen.
            lockWindow.Closed += (_, __) =>
            {
                Logger.LogInfo("LockWindow closed — screen unlocked, app staying resident.");
                _activeLockWindow = null;
                _appExiting = true;   // pause watchdog while unlocked
            };

            MainWindow = lockWindow;
            _appExiting = false;  // watchdog active while lock is shown
            lockWindow.Show();
        }

        // ------------------------------------------------------------------ //
        //  Power & session event handlers                                    //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Fired by Windows when the system suspends or resumes.
        /// On <see cref="PowerModes.Resume"/> we immediately re-show the lock
        /// window so the screen is secured the moment the user sits back down.
        /// </summary>
        private void OnPowerModeChanged(object sender, PowerModeChangedEventArgs e)
        {
            if (e.Mode == PowerModes.Resume)
            {
                Logger.LogInfo("System resumed from sleep/hibernate — re-locking screen.");
                Dispatcher.Invoke(() => ShowLockWindow());
            }
        }

        /// <summary>
        /// Fired when the Windows session is locked or unlocked (Win+L etc.).
        /// On <see cref="SessionSwitchReason.SessionUnlock"/> we re-show our
        /// lock window so the user must authenticate through our app as well.
        /// </summary>
        private void OnSessionSwitch(object sender, SessionSwitchEventArgs e)
        {
            if (e.Reason == SessionSwitchReason.SessionUnlock)
            {
                Logger.LogInfo("Windows session unlocked — re-locking screen.");
                Dispatcher.Invoke(() => ShowLockWindow());
            }
        }

        // ------------------------------------------------------------------ //
        //  Auto-start registration                                           //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Writes a registry Run entry so the lock screen launches
        /// automatically each time the current user logs in.
        ///
        /// Uses HKCU (Current User) rather than HKLM (Local Machine) so that
        /// admin rights are not required at runtime.
        /// </summary>
        private static void RegisterAutoStart()
        {
            try
            {
                string exePath = Assembly.GetExecutingAssembly().Location;
                using (RegistryKey key =
                    Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: true))
                {
                    if (key == null)
                    {
                        Logger.LogWarning("Could not open registry Run key for autostart.");
                        return;
                    }

                    // Only write if the value is missing or outdated
                    object existing = key.GetValue(RunKeyName);
                    if (existing?.ToString() != $"\"{exePath}\"")
                    {
                        key.SetValue(RunKeyName, $"\"{exePath}\"");
                        Logger.LogInfo("Autostart registry entry written.");
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.LogError("Failed to register autostart.", ex);
            }
        }

        // ------------------------------------------------------------------ //
        //  Watchdog                                                          //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Starts a background daemon thread that sleeps for 5 seconds and
        /// then checks whether the current process is still alive.  If the
        /// lock is somehow terminated (e.g. Task Manager), the watchdog
        /// re-launches the executable.
        ///
        /// The watchdog itself is a separate background thread within the same
        /// process — it therefore cannot survive if the entire process is
        /// killed.  For stronger self-healing, deploy a companion Windows
        /// Service or Scheduled Task set to restart on failure.  The README
        /// describes both approaches.
        ///
        /// Note: <see cref="_appExiting"/> is set to <c>true</c> on a normal
        /// unlock so the watchdog does not relaunch after an authorised exit.
        /// </summary>
        private void StartWatchdog()
        {
            string exePath = Assembly.GetExecutingAssembly().Location;

            _watchdogThread = new Thread(() =>
            {
                Thread.Sleep(TimeSpan.FromSeconds(10)); // Grace period at startup

                while (!_appExiting)
                {
                    Thread.Sleep(TimeSpan.FromSeconds(5));

                    if (_appExiting) break;

                    // Check if the lock window is still visible.
                    // If not, and we haven't explicitly exited, relaunch.
                    Dispatcher.Invoke(() =>
                    {
                        if (!_appExiting && (MainWindow == null || !MainWindow.IsVisible))
                        {
                            Logger.LogWarning(
                                "LockWindow is no longer visible — watchdog relaunching.");

                            Process.Start(new ProcessStartInfo
                            {
                                FileName = exePath,
                                UseShellExecute = true
                            });

                            // Terminate this instance — the new one takes over
                            _appExiting = true;
                            Environment.Exit(0);
                        }
                    });
                }
            })
            {
                IsBackground = true,
                Name = "SecureLock.Watchdog",
                Priority = ThreadPriority.BelowNormal
            };

            _watchdogThread.Start();
        }
    }

    // ---------------------------------------------------------------------- //
    //  Null-object implementation of FirebaseService                         //
    //  Used when no valid configuration is present (offline-only mode).      //
    // ---------------------------------------------------------------------- //

    /// <summary>
    /// A no-op FirebaseService that always reports as unavailable.
    /// Prevents null-reference exceptions in offline / misconfigured setups.
    /// Callers fall back to the local cache automatically.
    /// </summary>
    internal sealed class NullFirebaseService : FirebaseService
    {
        public NullFirebaseService() : base() { }

        // Always returns false → callers fall back to local cache
        public override System.Threading.Tasks.Task<bool> IsAvailableAsync(
            CancellationToken ct = default)
            => System.Threading.Tasks.Task.FromResult(false);

        // Silently ignore any upload attempts
        public override System.Threading.Tasks.Task SetPasswordAsync(
            string machineId, string encryptedPassword,
            CancellationToken ct = default)
            => System.Threading.Tasks.Task.CompletedTask;

        // Always returns null → no password found
        public override System.Threading.Tasks.Task<string> GetPasswordAsync(
            string machineId,
            CancellationToken ct = default)
            => System.Threading.Tasks.Task.FromResult<string>(null);
    }
}

