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
    ///      <see cref="UnlockSucceeded"/> directly without prompting the user.
    ///      Not affected by unlock_count.
    ///   2. Offline PIN (emergency, user-typed):
    ///      User types the fixed PIN set by the admin.  Each successful match
    ///      decrements the remaining unlock count.  When count reaches zero the
    ///      PIN is blocked until the admin resets it via the dashboard.
    ///   3. Master password (break-glass):
    ///      Always accepted as a fail-safe.  Not affected by unlock_count.
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

        /// <summary>
        /// Remaining PIN unlock count.
        ///   -1  = not yet loaded from cache/Firebase (show nothing)
        ///    0  = exhausted (PIN blocked)
        ///   >0  = available
        /// </summary>
        private int _unlockCountRemaining = -1;

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

            _unlockCommandService.UnlockRequested += OnAdminUnlockRequested;

            // Load count from cache immediately; background task will refresh from Firebase.
            LoadCountFromCache();
            _ = Task.Run(() => RefreshCountFromFirebaseAsync());
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

        public int UnlockCountRemaining
        {
            get => _unlockCountRemaining;
            private set
            {
                if (_unlockCountRemaining == value) return;
                _unlockCountRemaining = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(UnlockCountMessage));
                OnPropertyChanged(nameof(IsCountMessageVisible));
            }
        }

        /// <summary>Human-readable remaining-count label shown below the PIN input.</summary>
        public string UnlockCountMessage
        {
            get
            {
                if (_unlockCountRemaining < 0) return string.Empty;
                if (_unlockCountRemaining == 0) return "PIN usage limit reached. Contact your admin.";
                if (_unlockCountRemaining == 1) return "This is the last available unlock.";
                return $"{_unlockCountRemaining} PIN unlocks remaining.";
            }
        }

        /// <summary>Hide the counter row entirely while the count is loading (= -1).</summary>
        public bool IsCountMessageVisible => _unlockCountRemaining >= 0;

        // ------------------------------------------------------------------ //
        //  Commands / Events                                                  //
        // ------------------------------------------------------------------ //

        public ICommand UnlockCommand { get; }

        public event EventHandler UnlockSucceeded;

        // ------------------------------------------------------------------ //
        //  Admin remote unlock                                                //
        // ------------------------------------------------------------------ //

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
                StatusMessage = "Unlocked by admin…";
                UnlockSucceeded?.Invoke(this, EventArgs.Empty);
            });

            _ = Task.Run(async () =>
            {
                try
                {
                    await Logger.LogUnlockSuccessAsync(_machineId, isMasterPassword: false)
                        .ConfigureAwait(false);
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

                // Enforce unlock_count ONLY for OfflinePin matches.  Master
                // password and admin remote unlock remain fail-safes that always
                // work, even when the PIN is exhausted.
                if (result == PasswordMatchResult.OfflinePin && _unlockCountRemaining == 0)
                {
                    PostToUi(() =>
                    {
                        StatusMessage = "PIN usage limit reached. Contact your admin.";
                        IsUnlocking = false;
                    });
                    return;
                }

                if (result != PasswordMatchResult.NoMatch)
                {
                    _alreadyUnlocked = true;

                    // Decrement local cache SYNCHRONOUSLY before raising
                    // UnlockSucceeded.  If we deferred this to a background task,
                    // an immediate re-lock could spawn a new LockViewModel that
                    // reads the still-pre-decrement cache and grants a free unlock.
                    int newCount = -1;
                    if (result == PasswordMatchResult.OfflinePin)
                        newCount = _offlinePinService.DecrementLocalCache();

                    PostToUi(() =>
                    {
                        if (newCount >= 0) UnlockCountRemaining = newCount;
                        StatusMessage = "Unlocked successfully…";
                        UnlockSucceeded?.Invoke(this, EventArgs.Empty);
                    });

                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            if (result == PasswordMatchResult.OfflinePin)
                            {
                                await _offlinePinService
                                    .FlushPendingDecrementsAsync(_machineId)
                                    .ConfigureAwait(false);
                            }

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

        private async Task<PasswordMatchResult> ValidatePinAsync(SecureString secureInput)
        {
            string entered = SecureStringToString(secureInput);

            // Master password — instant fail-safe, bypasses count.
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
        //  Count loading                                                      //
        // ------------------------------------------------------------------ //

        private void LoadCountFromCache()
        {
            int? cached = _offlinePinService.ReadCachedCount();
            if (cached.HasValue)
                UnlockCountRemaining = cached.Value;
        }

        private async Task RefreshCountFromFirebaseAsync()
        {
            try
            {
                // Flush any pending offline decrements FIRST so we don't pull a
                // stale (higher) Firebase value and overwrite the local cache.
                await _offlinePinService
                    .FlushPendingDecrementsAsync(_machineId)
                    .ConfigureAwait(false);

                // If pending decrements are still on disk (Firebase unreachable),
                // local cache is authoritative — surface it and stop.
                if (_offlinePinService.HasPendingDecrements())
                {
                    int? local = _offlinePinService.ReadCachedCount();
                    if (local.HasValue) PostToUi(() => UnlockCountRemaining = local.Value);
                    return;
                }

                int? count = await _firebaseService
                    .GetUnlockCountAsync(_machineId)
                    .ConfigureAwait(false);

                if (count.HasValue)
                {
                    _offlinePinService.WriteCountCache(count.Value);
                    PostToUi(() => UnlockCountRemaining = count.Value);
                }
            }
            catch (Exception ex)
            {
                Logger.LogFirebaseError(ex, "LockViewModel.RefreshCountFromFirebase");
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
                    action();
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
