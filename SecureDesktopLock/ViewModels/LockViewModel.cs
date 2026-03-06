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
    ///   • Coordinate the password validation flow:
    ///       1. Try Firebase first (online mode).
    ///       2. Fall back to the local cached password (offline mode).
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
                    PostToUi(() => StatusMessage = "Unlocked — starting session…");

                    // Rotate only the password that was used to unlock.
                    // Master password never triggers rotation.
                    if (result == PasswordMatchResult.CurrentPassword)
                    {
                        await _rotationService.RotateAsync(_machineId, isBackup: false)
                            .ConfigureAwait(false);
                    }
                    else if (result == PasswordMatchResult.BackupPassword)
                    {
                        await _rotationService.RotateAsync(_machineId, isBackup: true)
                            .ConfigureAwait(false);
                    }

                    await Logger.LogUnlockSuccessAsync(_machineId)
                        .ConfigureAwait(false);

                    // Raise the event on the UI thread
                    PostToUi(() => UnlockSucceeded?.Invoke(this, EventArgs.Empty));
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
        /// Compares the entered password against both the current and backup
        /// passwords.  Tries Firebase first; falls back to local cache if
        /// Firebase is unavailable.
        /// Also accepts the master password read from the config file as a
        /// fail-safe fallback without consulting Firebase or the cache.
        /// Returns which password was matched (or <see cref="PasswordMatchResult.NoMatch"/>).
        /// </summary>
        private async Task<PasswordMatchResult> ValidatePasswordAsync(SecureString secureInput)
        {
            // Convert SecureString → plain-text (in a controlled scope)
            string enteredPassword = SecureStringToString(secureInput);

            // ----------------------------------------------------------------
            // Master password: always accepted as a fail-safe fallback
            // ----------------------------------------------------------------
            if (!string.IsNullOrEmpty(_masterPassword) &&
                string.Equals(enteredPassword, _masterPassword, StringComparison.Ordinal))
            {
                enteredPassword = null;
                await Logger.LogUnlockSuccessAsync(_machineId, isMasterPassword: true)
                    .ConfigureAwait(false);
                return PasswordMatchResult.MasterPassword;
            }

            string encryptedCurrent = null;
            string encryptedBackup = null;
            bool usedCache = false;

            // --- Step 1: Attempt Firebase ---
            try
            {
                if (await _firebaseService.IsAvailableAsync().ConfigureAwait(false))
                {
                    encryptedCurrent = await _firebaseService
                        .GetPasswordAsync(_machineId)
                        .ConfigureAwait(false);

                    encryptedBackup = await _firebaseService
                        .GetBackupPasswordAsync(_machineId)
                        .ConfigureAwait(false);

                    // Keep the local cache in sync with the Firebase values
                    if (encryptedCurrent != null)
                        _rotationService.WriteCache(encryptedCurrent);
                    if (encryptedBackup != null)
                        _rotationService.WriteBackupCache(encryptedBackup);
                }
            }
            catch (Exception ex)
            {
                Logger.LogFirebaseError(ex, "ValidatePassword.GetFromFirebase");
            }

            // --- Step 2: Fall back to local cache ---
            if (encryptedCurrent == null && encryptedBackup == null)
            {
                encryptedCurrent = _rotationService.ReadCachedPassword();
                encryptedBackup = _rotationService.ReadBackupCachedPassword();
                usedCache = encryptedCurrent != null || encryptedBackup != null;

                if (usedCache)
                    PostToUi(() => StatusMessage = "Offline mode — using cached password.");
                else
                {
                    PostToUi(() => StatusMessage =
                        "No password record found. Contact your administrator.");
                    return PasswordMatchResult.NoMatch;
                }
            }

            // --- Step 3: Compare against current password ---
            try
            {
                if (encryptedCurrent != null &&
                    _encryptionService.TryDecrypt(encryptedCurrent, out string currentPlain))
                {
                    if (string.Equals(enteredPassword, currentPlain, StringComparison.Ordinal))
                    {
                        currentPlain = null;
                        return PasswordMatchResult.CurrentPassword;
                    }
                    currentPlain = null;
                }

                // --- Step 4: Compare against backup password ---
                if (encryptedBackup != null &&
                    _encryptionService.TryDecrypt(encryptedBackup, out string backupPlain))
                {
                    if (string.Equals(enteredPassword, backupPlain, StringComparison.Ordinal))
                    {
                        backupPlain = null;
                        return PasswordMatchResult.BackupPassword;
                    }
                    backupPlain = null;
                }

                return PasswordMatchResult.NoMatch;
            }
            finally
            {
                // Zero the entered password string (best-effort in managed code)
                enteredPassword = null;
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
