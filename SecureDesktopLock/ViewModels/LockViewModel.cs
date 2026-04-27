using SecureDesktopLock.Models;
using SecureDesktopLock.Services;
using SecureDesktopLock.Utils;
using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Security;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;

namespace SecureDesktopLock.ViewModels
{
    /// <summary>
    /// ViewModel for the <c>LockWindow</c>.
    ///
    /// Unlock paths
    /// ------------
    ///   1. Admin remote command (primary, online):
    ///      <see cref="UnlockCommandService"/> raises an event → we fire
    ///      <see cref="UnlockSucceeded"/> directly without prompting the user
    ///      and WITHOUT rotating the offline PIN.
    ///   2. Offline PIN (emergency, user-typed):
    ///      User types the PIN into the PasswordBox → we compare against the
    ///      cached and Firebase-fetched values.  On match, the PIN is rotated
    ///      so it is single-use.
    ///   3. Master password (break-glass):
    ///      Always accepted as a fail-safe regardless of all other paths.
    ///      Never triggers rotation.
    /// </summary>
    public sealed class LockViewModel : INotifyPropertyChanged
    {
        // ------------------------------------------------------------------ //
        //  Services                                                           //
        // ------------------------------------------------------------------ //
        private readonly FirebaseService _firebaseService;
        private readonly EncryptionService _encryptionService;
        private readonly OfflinePinService _offlinePinService;
        private readonly UnlockCommandService _unlockCommandService;

        /// <summary>
        /// Master password loaded from App.config.  Always accepted as a
        /// fail-safe.  Empty string disables this path safely.
        /// </summary>
        private readonly string _masterPassword;

        // ------------------------------------------------------------------ //
        //  State                                                              //
        // ------------------------------------------------------------------ //
        private string _statusMessage = "Waiting for admin to unlock…";
        private bool _isUnlocking = false;
        private int _failureCount = 0;
        private volatile bool _alreadyUnlocked = false;
        private readonly string _machineId;
        private readonly Dispatcher _uiDispatcher;

        // ------------------------------------------------------------------ //
        //  Constructor                                                        //
        // ------------------------------------------------------------------ //

        public LockViewModel(
            FirebaseService firebaseService,
            EncryptionService encryptionService,
            OfflinePinService offlinePinService,
            UnlockCommandService unlockCommandService)
        {
            _firebaseService = firebaseService
                ?? throw new ArgumentNullException(nameof(firebaseService));
            _encryptionService = encryptionService
                ?? throw new ArgumentNullException(nameof(encryptionService));
            _offlinePinService = offlinePinService
                ?? throw new ArgumentNullException(nameof(offlinePinService));
            _unlockCommandService = unlockCommandService
                ?? throw new ArgumentNullException(nameof(unlockCommandService));

            _machineId = MachineInfo.GetMachineId();
            // Capture the Application's UI dispatcher for reliable UI marshalling.
            // SynchronizationContext.Current can be null in edge cases (e.g.
            // immediately after sleep/resume), causing callbacks to run on the
            // ThreadPool — which then throws when calling Window.Close().
            _uiDispatcher = Application.Current?.Dispatcher
                            ?? Dispatcher.CurrentDispatcher;

            _masterPassword = System.Configuration.ConfigurationManager
                                  .AppSettings["MasterPassword"]
                              ?? string.Empty;

            if (string.IsNullOrEmpty(_masterPassword))
                Logger.LogInfo("[LockViewModel] 'MasterPassword' not set in App.config; master-password unlock disabled.");
            else
                Logger.LogInfo("[LockViewModel] Master password loaded from App.config.");

            UnlockCommand = new RelayCommand(
                execute: OnUnlockCommandExecuted,
                canExecute: _ => !IsUnlocking);

            // Subscribe to admin remote-unlock command.
            _unlockCommandService.UnlockRequested += OnAdminUnlockRequested;
        }

        // ------------------------------------------------------------------ //
        //  Bindable properties                                                //
        // ------------------------------------------------------------------ //

        public string StatusMessage
        {
            get => _statusMessage;
            private set { _statusMessage = value; OnPropertyChanged(); }
        }

        public bool IsUnlocking
        {
            get => _isUnlocking;
            private set { _isUnlocking = value; OnPropertyChanged(); }
        }

        public string MachineId => _machineId;

        // ------------------------------------------------------------------ //
        //  Commands                                                           //
        // ------------------------------------------------------------------ //

        public ICommand UnlockCommand { get; }

        // ------------------------------------------------------------------ //
        //  Events                                                             //
        // ------------------------------------------------------------------ //

        public event EventHandler UnlockSucceeded;

        // ------------------------------------------------------------------ //
        //  Admin remote unlock                                                //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Called by <see cref="UnlockCommandService"/> on a background thread
        /// when admin clicks "Unlock" on the dashboard.  No password prompt,
        /// no PIN rotation — just close the lock window.
        /// </summary>
        private void OnAdminUnlockRequested(object sender, EventArgs e)
        {
            Logger.LogInfo("[LockViewModel] OnAdminUnlockRequested fired (background thread).");

            if (_alreadyUnlocked)
            {
                Logger.LogInfo("[LockViewModel] _alreadyUnlocked=true, ignoring duplicate.");
                return;
            }
            _alreadyUnlocked = true;

            PostToUi(() =>
            {
                Logger.LogInfo("[LockViewModel] Posting unlock to UI thread — invoking UnlockSucceeded.");
                StatusMessage = "Unlocked by admin…";
                UnlockSucceeded?.Invoke(this, EventArgs.Empty);
                Logger.LogInfo("[LockViewModel] UnlockSucceeded invocation returned.");
            });

            _ = Task.Run(async () =>
            {
                try
                {
                    await Logger.LogUnlockSuccessAsync(_machineId, isMasterPassword: false)
                        .ConfigureAwait(false);
                    Logger.LogInfo("[LockViewModel] Unlocked via admin remote command.");
                }
                catch (Exception ex)
                {
                    Logger.LogError("Failed to log admin-unlock success.", ex);
                }
            });
        }

        // ------------------------------------------------------------------ //
        //  Password / PIN unlock flow                                         //
        // ------------------------------------------------------------------ //

        private enum PasswordMatchResult
        {
            NoMatch,
            MasterPassword,
            OfflinePin
        }

        private async void OnUnlockCommandExecuted(object parameter)
        {
            if (IsUnlocking) return;

            SecureString securePassword = parameter as SecureString;
            if (securePassword == null || securePassword.Length == 0)
            {
                StatusMessage = "Please enter your PIN.";
                return;
            }

            IsUnlocking = true;
            StatusMessage = "Verifying…";

            try
            {
                PasswordMatchResult result = await ValidatePinAsync(securePassword)
                    .ConfigureAwait(false);

                if (result != PasswordMatchResult.NoMatch)
                {
                    _alreadyUnlocked = true;

                    PostToUi(() =>
                    {
                        StatusMessage = "Unlocked successfully…";
                        UnlockSucceeded?.Invoke(this, EventArgs.Empty);
                    });

                    // Background post-unlock: rotate only if matched OfflinePin.
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            if (result == PasswordMatchResult.OfflinePin)
                                await _offlinePinService.RotateAsync(_machineId)
                                    .ConfigureAwait(false);

                            await Logger.LogUnlockSuccessAsync(
                                    _machineId,
                                    isMasterPassword: result == PasswordMatchResult.MasterPassword)
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
                        StatusMessage = $"Incorrect PIN. (Attempt {_failureCount})";
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
                    StatusMessage = "An unexpected error occurred. Please try again.";
                    IsUnlocking = false;
                });
            }
        }

        /// <summary>
        /// Validates the entered PIN against the master password and the
        /// offline PIN (cache-first, Firebase-second).
        /// </summary>
        private async Task<PasswordMatchResult> ValidatePinAsync(SecureString secureInput)
        {
            string entered = SecureStringToString(secureInput);

            // Master password — instant fail-safe.
            if (!string.IsNullOrEmpty(_masterPassword) &&
                string.Equals(entered, _masterPassword, StringComparison.Ordinal))
            {
                entered = null;
                return PasswordMatchResult.MasterPassword;
            }

            // Kick off Firebase fetch in background; compare cache first.
            Task<string> firebaseTask = null;
            try
            {
                firebaseTask = _firebaseService.GetOfflinePinAsync(_machineId);
            }
            catch (Exception ex)
            {
                Logger.LogFirebaseError(ex, "ValidatePin.StartFetch");
            }

            string cached = _offlinePinService.ReadCachedPin();

            if (cached != null &&
                ComparePin(entered, cached) == PasswordMatchResult.OfflinePin)
            {
                _ = SyncCacheFromFirebaseAsync(firebaseTask);
                entered = null;
                return PasswordMatchResult.OfflinePin;
            }

            // Cache miss → wait for Firebase.
            string fromFirebase = null;
            if (firebaseTask != null)
            {
                try
                {
                    fromFirebase = await firebaseTask.ConfigureAwait(false);
                    if (fromFirebase != null)
                        _offlinePinService.WriteCache(fromFirebase);
                }
                catch (Exception ex)
                {
                    Logger.LogFirebaseError(ex, "ValidatePin.AwaitFetch");
                }
            }

            if (fromFirebase == null)
            {
                fromFirebase = cached;

                if (fromFirebase != null)
                    PostToUi(() => StatusMessage = "Offline mode — using cached PIN.");
                else
                {
                    entered = null;
                    PostToUi(() => StatusMessage =
                        "No PIN available for this machine. Contact your admin.");
                    return PasswordMatchResult.NoMatch;
                }
            }

            try
            {
                return ComparePin(entered, fromFirebase);
            }
            finally
            {
                entered = null;
            }
        }

        private PasswordMatchResult ComparePin(string entered, string encryptedStored)
        {
            if (encryptedStored == null) return PasswordMatchResult.NoMatch;

            if (!_encryptionService.TryDecrypt(encryptedStored, out string plain))
                return PasswordMatchResult.NoMatch;

            bool match = string.Equals(entered, plain, StringComparison.Ordinal);
            plain = null;
            return match ? PasswordMatchResult.OfflinePin : PasswordMatchResult.NoMatch;
        }

        private async Task SyncCacheFromFirebaseAsync(Task<string> fetchTask)
        {
            if (fetchTask == null) return;
            try
            {
                string fresh = await fetchTask.ConfigureAwait(false);
                if (fresh != null) _offlinePinService.WriteCache(fresh);
            }
            catch (Exception ex)
            {
                Logger.LogFirebaseError(ex, "ValidatePin.BackgroundCacheSync");
            }
        }

        // ------------------------------------------------------------------ //
        //  Helpers                                                            //
        // ------------------------------------------------------------------ //

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

        private void PostToUi(Action action)
        {
            try
            {
                if (_uiDispatcher.CheckAccess())
                    action();                       // already on UI thread
                else
                    _uiDispatcher.BeginInvoke(action);
            }
            catch (Exception ex)
            {
                Logger.LogError("[LockViewModel] PostToUi dispatch failed.", ex);
            }
        }

        // ------------------------------------------------------------------ //
        //  INotifyPropertyChanged                                             //
        // ------------------------------------------------------------------ //

        public event PropertyChangedEventHandler PropertyChanged;

        private void OnPropertyChanged([CallerMemberName] string name = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
