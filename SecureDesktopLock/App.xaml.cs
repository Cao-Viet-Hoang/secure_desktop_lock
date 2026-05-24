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
        private OfflinePinService _offlinePinService;
        private UnlockCommandService _unlockCommandService;
        private HeartbeatService _heartbeatService;
        private ReLockService _reLockService;

        // Watchdog thread
        private Thread _watchdogThread;
        private bool _appExiting = false;

        // Active lock window (null when screen is unlocked)
        private LockWindow _activeLockWindow;

        // Re-lock warning overlay (null when not shown)
        private ReLockWarningWindow _warningWindow;

        // Unlock toast notification (null when not shown)
        private UnlockToastWindow _unlockToast;

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

            string machineId = MachineInfo.GetMachineId();

            _offlinePinService = new OfflinePinService(fs, _encryptionService);
            _unlockCommandService = new UnlockCommandService(fs, machineId);
            _heartbeatService = new HeartbeatService(fs, machineId);

            // ── 4b. Re-lock service ───────────────────────────────────────
            _reLockService = new ReLockService(fs);
            _reLockService.WarningTick += OnReLockWarningTick;
            _reLockService.ReLockRequested += OnReLockRequested;

            // ── 5. Initialise offline PIN + unlock count (fire-and-forget) ──
            // Pushes any pending count decrements first, then syncs PIN and
            // unlock_count from Firebase to the local cache.
            _ = _offlinePinService.InitializeAsync(machineId);

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

            _unlockCommandService?.Dispose();
            _heartbeatService?.Dispose();
            _reLockService?.Dispose();
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
                _offlinePinService,
                _unlockCommandService);

            LockWindow lockWindow = new LockWindow();
            lockWindow.SetViewModel(viewModel);
            _activeLockWindow = lockWindow;

            // After a successful unlock the window closes.
            // Stay resident so sleep/resume events can re-lock the screen.
            lockWindow.Closed += async (_, __) =>
            {
                Logger.LogInfo("LockWindow closed — screen unlocked, app staying resident.");
                _activeLockWindow = null;
                _appExiting = true;   // pause watchdog while unlocked

                // Stop signalling services — heartbeat + command listener only
                // make sense while we're showing the lock screen.
                _unlockCommandService?.Stop();
                _heartbeatService?.Stop();

                // Release keyboard hook so Win, Alt, etc. work normally
                _keyboardHook?.Stop();

                // Start the auto re-lock countdown and get the resolved interval
                string mid = MachineInfo.GetMachineId();
                int relockSeconds = await _reLockService.StartAsync(mid);

                // Show toast notification with relock time info (auto-closes after 5 s)
                ShowUnlockToast(relockSeconds);
            };

            MainWindow = lockWindow;
            _appExiting = false;  // watchdog active while lock is shown

            // Cancel any running re-lock timer (avoid double-trigger)
            _reLockService?.Cancel();
            CloseWarningWindow();
            CloseUnlockToast();

            // Re-install keyboard hook to block Win, Alt+Tab, etc. while locked
            _keyboardHook?.Start();

            // Start signalling services bound to lock-window lifecycle.
            _unlockCommandService?.Start();
            _heartbeatService?.Start();

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
        //  Re-lock event handlers                                            //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Called every second during the warning window.
        /// Shows (or updates) the countdown overlay.
        /// </summary>
        private void OnReLockWarningTick(object sender, int secondsRemaining)
        {
            Dispatcher.Invoke(() =>
            {
                if (_warningWindow == null || !_warningWindow.IsVisible)
                {
                    _warningWindow = new ReLockWarningWindow();
                    _warningWindow.Show();
                }
                _warningWindow.UpdateCountdown(secondsRemaining);
            });
        }

        /// <summary>
        /// Called when the re-lock countdown reaches zero.
        /// Closes the warning overlay and re-shows the lock window.
        /// </summary>
        private void OnReLockRequested(object sender, EventArgs e)
        {
            Dispatcher.Invoke(() =>
            {
                Logger.LogInfo("[ReLock] Timer expired — re-locking screen.");
                CloseWarningWindow();
                ShowLockWindow();
            });
        }

        /// <summary>
        /// Closes the warning overlay if it is currently visible.
        /// </summary>
        private void CloseWarningWindow()
        {
            if (_warningWindow != null)
            {
                _warningWindow.Close();
                _warningWindow = null;
            }
        }

        /// <summary>
        /// Shows a toast notification at the bottom-right corner that tells
        /// the user how long until the screen re-locks and the exact clock
        /// time.  The toast dismisses itself after 5 seconds.
        /// </summary>
        /// <param name="relockIntervalSeconds">
        /// The re-lock interval in seconds (0 = feature disabled).
        /// </param>
        private void ShowUnlockToast(int relockIntervalSeconds)
        {
            // Close any previous toast that might still be fading
            if (_unlockToast != null)
            {
                _unlockToast.Close();
                _unlockToast = null;
            }

            _unlockToast = new UnlockToastWindow();
            _unlockToast.SetRelockInfo(relockIntervalSeconds);
            _unlockToast.Closed += (_, __) => _unlockToast = null;
            _unlockToast.Show();
        }

        /// <summary>
        /// Closes the unlock toast if it is currently visible.
        /// </summary>
        private void CloseUnlockToast()
        {
            if (_unlockToast != null)
            {
                _unlockToast.Close();
                _unlockToast = null;
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

        public override System.Threading.Tasks.Task<bool> IsAvailableAsync(
            CancellationToken ct = default)
            => System.Threading.Tasks.Task.FromResult(false);

        public override System.Threading.Tasks.Task<string> GetOfflinePinAsync(
            string machineId,
            CancellationToken ct = default)
            => System.Threading.Tasks.Task.FromResult<string>(null);

        public override System.Threading.Tasks.Task SetOfflinePinAsync(
            string machineId, string encryptedPin,
            CancellationToken ct = default)
            => System.Threading.Tasks.Task.CompletedTask;

        public override System.Threading.Tasks.Task<UnlockRequest> GetUnlockRequestAsync(
            string machineId,
            CancellationToken ct = default)
            => System.Threading.Tasks.Task.FromResult<UnlockRequest>(null);

        public override System.Threading.Tasks.Task DeleteUnlockRequestAsync(
            string machineId,
            CancellationToken ct = default)
            => System.Threading.Tasks.Task.CompletedTask;

        public override System.Threading.Tasks.Task SetLastSeenAsync(
            string machineId,
            CancellationToken ct = default)
            => System.Threading.Tasks.Task.CompletedTask;

        public override System.Threading.Tasks.Task<int?> GetReLockIntervalAsync(
            string machineId,
            CancellationToken ct = default)
            => System.Threading.Tasks.Task.FromResult<int?>(null);

        public override System.Threading.Tasks.Task ClearLastSeenAsync(string machineId)
            => System.Threading.Tasks.Task.CompletedTask;

        public override System.Threading.Tasks.Task<int?> GetUnlockCountAsync(
            string machineId,
            CancellationToken ct = default)
            => System.Threading.Tasks.Task.FromResult<int?>(null);

        public override System.Threading.Tasks.Task SetUnlockCountAsync(
            string machineId, int count,
            CancellationToken ct = default)
            => System.Threading.Tasks.Task.CompletedTask;
    }
}

