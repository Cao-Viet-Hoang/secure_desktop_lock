using SecureDesktopLock.Models;
using SecureDesktopLock.Services;
using SecureDesktopLock.Utils;
using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Security;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;

namespace SecureDesktopLock.ViewModels
{
    /// <summary>
    /// ViewModel for the <c>LockWindow</c>.
    ///
    /// Responsibilities
    /// ----------------
    ///   • Hold state exposed to the XAML bindings (status message, busy flag).
    ///   • Coordinate the password validation flow (cache-first strategy):
    ///       1. Kick off Firebase fetch in the background immediately.
    ///       2. Compare against local cache (instant, no network wait).
    ///          – Cache hit  → unlock immediately; Firebase sync continues in background.
    ///          – Cache miss → await the in-flight Firebase tasks, compare fresh values.
    ///       3. If Firebase is also unavailable, retry against whatever the cache holds.
    ///   • Trigger password rotation (<see cref="PasswordRotationService"/>) on
    ///     success — only the matched password (current or backup) is rotated.
    ///   • Raise <see cref="UnlockSucceeded"/> event for the View to close itself.
    ///
    /// Threading
    /// ---------
    ///   All public properties are updated on the UI thread via the captured
    ///   <see cref="SynchronizationContext"/>.  Async command bodies run on
    ///   the thread pool for I/O but marshal back for property updates.
    /// </summary>
    public sealed class LockViewModel : INotifyPropertyChanged
    {
        // ------------------------------------------------------------------ //
        //  Services                                                           //
        // ------------------------------------------------------------------ //
        private readonly FirebaseService _firebaseService;
        private readonly EncryptionService _encryptionService;
        private readonly PasswordRotationService _rotationService;

        /// <summary>
        /// Master password loaded from the Firebase config JSON file at startup.
        /// Always accepted as a fail-safe fallback regardless of mode.
        /// To change it, update the <c>master_password</c> field in
        /// <c>firebase_config.json</c> and restart the application.
        /// </summary>
        private readonly string _masterPassword;

        // ------------------------------------------------------------------ //
        //  State                                                              //
        // ------------------------------------------------------------------ //
        private string _statusMessage = string.Empty;
        private bool _isUnlocking = false;
        private int _failureCount = 0;
        private readonly string _machineId;

        // UI-thread synchronisation context captured at construction time
        private readonly SynchronizationContext _uiContext;

        // ------------------------------------------------------------------ //
        //  Constructor                                                        //
        // ------------------------------------------------------------------ //

        public LockViewModel(
            FirebaseService firebaseService,
            EncryptionService encryptionService,
            PasswordRotationService rotationService)
        {
            _firebaseService = firebaseService
                ?? throw new ArgumentNullException(nameof(firebaseService));
            _encryptionService = encryptionService
                ?? throw new ArgumentNullException(nameof(encryptionService));
            _rotationService = rotationService
                ?? throw new ArgumentNullException(nameof(rotationService));

            _machineId = MachineInfo.GetMachineId();
            _uiContext = SynchronizationContext.Current
                         ?? new SynchronizationContext();

            // Load master password from App.config key "MasterPassword".
            // Falls back to empty string if absent; an empty string will
            // never match real user input so the app starts safely.
            _masterPassword = System.Configuration.ConfigurationManager
                                  .AppSettings["MasterPassword"]
                              ?? string.Empty;

            if (string.IsNullOrEmpty(_masterPassword))
                Logger.LogInfo("[LockViewModel] 'MasterPassword' not set in App.config; master-password unlock disabled.");
            else
                Logger.LogInfo("[LockViewModel] Master password loaded from App.config.");

            // --- Commands ---
            UnlockCommand = new RelayCommand(
                execute: OnUnlockCommandExecuted,
                canExecute: _ => !IsUnlocking);
        }

        // ------------------------------------------------------------------ //
        //  Bindable properties                                                //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Status message displayed beneath the password box.
        /// Updated after each validation attempt.
        /// </summary>
        public string StatusMessage
        {
            get => _statusMessage;
            private set { _statusMessage = value; OnPropertyChanged(); }
        }

        /// <summary>
        /// <c>true</c> while an async unlock operation is in flight.
        /// Disables the Unlock button and shows a visual busy state.
        /// </summary>
        public bool IsUnlocking
        {
            get => _isUnlocking;
            private set { _isUnlocking = value; OnPropertyChanged(); }
        }

        /// <summary>Current machine identifier (shown for diagnostics).</summary>
        public string MachineId => _machineId;

        // ------------------------------------------------------------------ //
        //  Commands                                                           //
        // ------------------------------------------------------------------ //

        /// <summary>Bound to the "Unlock" button in the View.</summary>
        public ICommand UnlockCommand { get; }

        // ------------------------------------------------------------------ //
        //  Events                                                             //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Fired on the UI thread when authentication succeeds.
        /// The View should close the lock window in response.
        /// </summary>
        public event EventHandler UnlockSucceeded;

        // ------------------------------------------------------------------ //
        //  Unlock flow                                                        //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Result of a password validation attempt indicating which password
        /// (if any) was matched.
        /// </summary>
        private enum PasswordMatchResult
        {
            NoMatch,
            MasterPassword,
            CurrentPassword,
            BackupPassword
        }

        /// <summary>
        /// Entry-point called by the command binding.  Receives the
        /// <see cref="SecureString"/> directly from the <c>PasswordBox</c>
        /// via the CommandParameter binding (see LockWindow XAML).
        /// </summary>
        private async void OnUnlockCommandExecuted(object parameter)
        {
            if (IsUnlocking) return;

            SecureString securePassword = parameter as SecureString;
            if (securePassword == null || securePassword.Length == 0)
            {
                StatusMessage = "Please enter the password.";
                return;
            }

            IsUnlocking = true;
            StatusMessage = "Verifying…";

            try
            {
                PasswordMatchResult result = await ValidatePasswordAsync(securePassword)
                    .ConfigureAwait(false);

                if (result != PasswordMatchResult.NoMatch)
                {
                    // Close the lock screen immediately — the user should never
                    // wait for rotation or logging.  Both are fire-and-forget.
                    PostToUi(() =>
                    {
                        StatusMessage = "Unlocked — starting session…";
                        UnlockSucceeded?.Invoke(this, EventArgs.Empty);
                    });

                    // Rotation and logging run in the background after the
                    // window is already gone.  Errors are logged but never
                    // surfaced to the (now unlocked) user.
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            if (result == PasswordMatchResult.CurrentPassword)
                                await _rotationService.RotateAsync(_machineId, isBackup: false)
                                    .ConfigureAwait(false);
                            else if (result == PasswordMatchResult.BackupPassword)
                                await _rotationService.RotateAsync(_machineId, isBackup: true)
                                    .ConfigureAwait(false);

                            await Logger.LogUnlockSuccessAsync(_machineId)
                                .ConfigureAwait(false);
                        }
                        catch (Exception ex)
                        {
                            Logger.LogError("Background post-unlock task failed.", ex);
                        }
                    });
                }
                else
                {
                    _failureCount++;
                    PostToUi(() =>
                    {
                        StatusMessage = $"Incorrect password. (Attempt {_failureCount})";
                        IsUnlocking = false;
                    });

                    await Logger.LogUnlockFailureAsync(_machineId, _failureCount)
                        .ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                Logger.LogError("Unexpected error during unlock.", ex);
                PostToUi(() =>
                {
                    StatusMessage = "An error occurred. Please try again.";
                    IsUnlocking = false;
                });
            }
        }

        /// <summary>
        /// Validates the entered password using a cache-first strategy.
        ///
        /// Flow
        /// ----
        ///   1. Firebase fetch tasks are started immediately (background).
        ///   2. Local cache is read synchronously (no network cost).
        ///   3. If the cache contains a match → return immediately; the
        ///      in-flight Firebase tasks keep running to refresh the cache.
        ///   4. If no cache match (or cache is cold) → await the Firebase
        ///      tasks and compare against the fresh values.
        ///   5. If Firebase is also unavailable → fall back to the already-read
        ///      cache values (true offline mode).
        ///
        /// Also accepts the master password as an instant fail-safe regardless
        /// of all other paths.
        /// </summary>
        private async Task<PasswordMatchResult> ValidatePasswordAsync(SecureString secureInput)
        {
            // Convert SecureString → plain-text (in a controlled scope)
            string enteredPassword = SecureStringToString(secureInput);

            // ----------------------------------------------------------------
            // Master password: instant fail-safe, no cache/Firebase needed
            // ----------------------------------------------------------------
            if (!string.IsNullOrEmpty(_masterPassword) &&
                string.Equals(enteredPassword, _masterPassword, StringComparison.Ordinal))
            {
                enteredPassword = null;
                await Logger.LogUnlockSuccessAsync(_machineId, isMasterPassword: true)
                    .ConfigureAwait(false);
                return PasswordMatchResult.MasterPassword;
            }

            // ----------------------------------------------------------------
            // Step 1: Kick off Firebase fetch in background immediately.
            //         Do NOT await yet — we want the cache comparison to happen
            //         in parallel while the network requests are in flight.
            // ----------------------------------------------------------------
            Task<string> firebaseCurrentTask = null;
            Task<string> firebaseBackupTask = null;
            try
            {
                firebaseCurrentTask = _firebaseService.GetPasswordAsync(_machineId);
                firebaseBackupTask = _firebaseService.GetBackupPasswordAsync(_machineId);
            }
            catch (Exception ex)
            {
                Logger.LogFirebaseError(ex, "ValidatePassword.StartFirebaseFetch");
            }

            // ----------------------------------------------------------------
            // Step 2: Read local cache synchronously (instant, no network).
            // ----------------------------------------------------------------
            string cachedCurrent = _rotationService.ReadCachedPassword();
            string cachedBackup = _rotationService.ReadBackupCachedPassword();

            // ----------------------------------------------------------------
            // Step 3: Cache-first comparison.
            //         If the cache has a match we unlock right away and let the
            //         Firebase tasks finish in the background to keep the cache
            //         fresh for the next unlock.
            // ----------------------------------------------------------------
            if (cachedCurrent != null || cachedBackup != null)
            {
                PasswordMatchResult cacheResult =
                    ComparePasswords(enteredPassword, cachedCurrent, cachedBackup);

                if (cacheResult != PasswordMatchResult.NoMatch)
                {
                    // Sync Firebase → cache in background; don't block the unlock.
                    _ = SyncCacheFromFirebaseAsync(firebaseCurrentTask, firebaseBackupTask);
                    enteredPassword = null;
                    return cacheResult;
                }
            }

            // ----------------------------------------------------------------
            // Step 4: Cache miss (cold start) or wrong password in cache.
            //         Await the already-running Firebase tasks for fresh data.
            // ----------------------------------------------------------------
            string encryptedCurrent = null;
            string encryptedBackup = null;

            if (firebaseCurrentTask != null && firebaseBackupTask != null)
            {
                try
                {
                    await Task.WhenAll(firebaseCurrentTask, firebaseBackupTask)
                        .ConfigureAwait(false);

                    encryptedCurrent = firebaseCurrentTask.Result;
                    encryptedBackup = firebaseBackupTask.Result;

                    // Keep cache in sync
                    if (encryptedCurrent != null)
                        _rotationService.WriteCache(encryptedCurrent);
                    if (encryptedBackup != null)
                        _rotationService.WriteBackupCache(encryptedBackup);
                }
                catch (Exception ex)
                {
                    Logger.LogFirebaseError(ex, "ValidatePassword.AwaitFirebase");
                }
            }

            // ----------------------------------------------------------------
            // Step 5: If Firebase returned nothing (offline), fall back to the
            //         cache values that were already read in Step 2.
            // ----------------------------------------------------------------
            if (encryptedCurrent == null && encryptedBackup == null)
            {
                encryptedCurrent = cachedCurrent;
                encryptedBackup = cachedBackup;

                if (encryptedCurrent != null || encryptedBackup != null)
                    PostToUi(() => StatusMessage = "Offline mode — using cached password.");
                else
                {
                    enteredPassword = null;
                    PostToUi(() => StatusMessage =
                        "No password record found. Contact your administrator.");
                    return PasswordMatchResult.NoMatch;
                }
            }

            try
            {
                return ComparePasswords(enteredPassword, encryptedCurrent, encryptedBackup);
            }
            finally
            {
                enteredPassword = null;
            }
        }

        /// <summary>
        /// Compares <paramref name="enteredPassword"/> against the decrypted
        /// current and backup passwords in order.
        /// Returns the first match, or <see cref="PasswordMatchResult.NoMatch"/>.
        /// </summary>
        private PasswordMatchResult ComparePasswords(
            string enteredPassword,
            string encryptedCurrent,
            string encryptedBackup)
        {
            if (encryptedCurrent != null &&
                _encryptionService.TryDecrypt(encryptedCurrent, out string currentPlain))
            {
                bool match = string.Equals(enteredPassword, currentPlain, StringComparison.Ordinal);
                currentPlain = null;
                if (match) return PasswordMatchResult.CurrentPassword;
            }

            if (encryptedBackup != null &&
                _encryptionService.TryDecrypt(encryptedBackup, out string backupPlain))
            {
                bool match = string.Equals(enteredPassword, backupPlain, StringComparison.Ordinal);
                backupPlain = null;
                if (match) return PasswordMatchResult.BackupPassword;
            }

            return PasswordMatchResult.NoMatch;
        }

        /// <summary>
        /// Awaits the already-running Firebase tasks and writes their results
        /// to the local cache.  Intended to be called fire-and-forget
        /// (<c>_ = SyncCacheFromFirebaseAsync(…)</c>) after a cache-hit unlock
        /// so the cache stays fresh without blocking the user.
        /// All errors are caught and logged.
        /// </summary>
        private async Task SyncCacheFromFirebaseAsync(
            Task<string> currentTask,
            Task<string> backupTask)
        {
            if (currentTask == null || backupTask == null) return;
            try
            {
                await Task.WhenAll(currentTask, backupTask).ConfigureAwait(false);

                string current = currentTask.Result;
                string backup = backupTask.Result;

                if (current != null) _rotationService.WriteCache(current);
                if (backup != null) _rotationService.WriteBackupCache(backup);

                Logger.LogInfo("[LockViewModel] Background Firebase→cache sync completed.");
            }
            catch (Exception ex)
            {
                Logger.LogFirebaseError(ex, "ValidatePassword.BackgroundCacheSync");
            }
        }

        // ------------------------------------------------------------------ //
        //  Helpers                                                            //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Converts a <see cref="SecureString"/> to a plain <see cref="string"/>.
        ///
        /// SECURITY NOTE: This temporarily exposes the password in managed
        /// memory.  The string is dereferenced immediately after comparison.
        /// On .NET Framework there is no safe way to avoid this for UI input —
        /// WPF's PasswordBox already copies the value to managed memory.
        /// </summary>
        private static string SecureStringToString(SecureString ss)
        {
            IntPtr ptr = System.Runtime.InteropServices.Marshal.SecureStringToGlobalAllocUnicode(ss);
            try
            {
                return System.Runtime.InteropServices.Marshal.PtrToStringUni(ptr);
            }
            finally
            {
                System.Runtime.InteropServices.Marshal.ZeroFreeGlobalAllocUnicode(ptr);
            }
        }

        /// <summary>
        /// Marshals an action back to the UI (dispatcher) thread.
        /// </summary>
        private void PostToUi(Action action)
        {
            _uiContext.Post(_ => action(), null);
        }

        // ------------------------------------------------------------------ //
        //  INotifyPropertyChanged                                             //
        // ------------------------------------------------------------------ //

        public event PropertyChangedEventHandler PropertyChanged;

        private void OnPropertyChanged([CallerMemberName] string name = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
