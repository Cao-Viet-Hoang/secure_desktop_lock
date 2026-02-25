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
    ///     success so every unlock consumes a unique one-time password.
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
        /// Master password that is always accepted regardless of mode.
        /// This serves as a fail-safe when generated passwords cannot be
        /// retrieved from Firebase or the local cache.
        /// </summary>
        private const string MasterPassword = "150501";

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
                bool success = await ValidatePasswordAsync(securePassword)
                    .ConfigureAwait(false);

                if (success)
                {
                    PostToUi(() => StatusMessage = "Unlocked — starting session…");

                    // Await rotation so the new password is fully saved to
                    // Firebase and local cache BEFORE the app is shut down.
                    // RotateAsync swallows its own errors internally, so this
                    // will never throw and adds only a brief network round-trip
                    // delay (~100-500 ms) before the window closes.
                    await _rotationService.RotateAsync(_machineId)
                        .ConfigureAwait(false);

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
        /// Compares the entered password against the stored password.
        /// Tries Firebase first; falls back to the local cache if
        /// Firebase is unavailable.
        ///
        /// In developer mode the comparison is made directly against the
        /// hardcoded <see cref="DevPassword"/> — Firebase and cache are
        /// not consulted, and password rotation is skipped.
        /// </summary>
        private async Task<bool> ValidatePasswordAsync(SecureString secureInput)
        {
            // Convert SecureString → plain-text (in a controlled scope)
            string enteredPassword = SecureStringToString(secureInput);

            // ----------------------------------------------------------------
            // Master password: always accepted as a fail-safe fallback
            // ----------------------------------------------------------------
            if (string.Equals(enteredPassword, MasterPassword, StringComparison.Ordinal))
            {
                enteredPassword = null;
                await Logger.LogUnlockSuccessAsync(_machineId, isMasterPassword: true)
                    .ConfigureAwait(false);
                return true;
            }

            string encryptedStored = null;
            bool usedCache = false;

            // --- Step 1: Attempt Firebase ---
            try
            {
                if (await _firebaseService.IsAvailableAsync().ConfigureAwait(false))
                {
                    encryptedStored = await _firebaseService
                        .GetPasswordAsync(_machineId)
                        .ConfigureAwait(false);

                    // Keep the local cache in sync with the Firebase value
                    if (encryptedStored != null)
                        _rotationService.WriteCache(encryptedStored);
                }
            }
            catch (Exception ex)
            {
                Logger.LogFirebaseError(ex, "ValidatePassword.GetFromFirebase");
            }

            // --- Step 2: Fall back to local cache ---
            if (encryptedStored == null)
            {
                encryptedStored = _rotationService.ReadCachedPassword();
                usedCache = encryptedStored != null;

                if (usedCache)
                    PostToUi(() => StatusMessage = "Offline mode — using cached password.");
                else
                {
                    PostToUi(() => StatusMessage =
                        "No password record found. Contact your administrator.");
                    return false;
                }
            }

            // --- Step 3: Read and compare ---
            try
            {
                if (_encryptionService.TryDecrypt(encryptedStored, out string storedPlain))
                {
                    bool match = string.Equals(
                        enteredPassword, storedPlain, StringComparison.Ordinal);

                    storedPlain = null;

                    return match;
                }
                else
                {
                    Logger.LogError(
                        $"Failed to read stored password for machineId={_machineId}.");
                    PostToUi(() => StatusMessage =
                        "Password data is missing or corrupt. " +
                        "Contact your administrator.");
                    return false;
                }
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
