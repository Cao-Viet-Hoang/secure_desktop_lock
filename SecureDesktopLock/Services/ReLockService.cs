using SecureDesktopLock.Utils;
using System;
using System.Configuration;
using System.Threading;
using System.Threading.Tasks;
using System.Timers;
using Timer = System.Timers.Timer;

namespace SecureDesktopLock.Services
{
    /// <summary>
    /// Manages the automatic re-lock countdown after a successful unlock.
    ///
    /// Behaviour
    /// ---------
    ///   1. After unlock, <see cref="StartAsync"/> is called with the machine ID.
    ///   2. The service reads <c>relock_after_seconds</c> from Firebase.
    ///      If Firebase is unavailable or returns 0, falls back to the
    ///      <c>ReLockAfterSeconds</c> key in App.config.
    ///   3. If the resolved interval is 0 the feature is disabled — no timer
    ///      starts and the screen stays unlocked indefinitely.
    ///   4. Otherwise a countdown runs.  When the remaining time drops to
    ///      <c>ReLockWarnBeforeSeconds</c> (App.config, default 30), the
    ///      <see cref="WarningTick"/> event fires every second with the
    ///      remaining seconds so the UI can show a countdown overlay.
    ///   5. When the countdown reaches 0 the <see cref="ReLockRequested"/>
    ///      event fires, signalling <c>App.xaml.cs</c> to re-show the
    ///      lock window.
    ///   6. <see cref="Cancel"/> stops the timer at any time (e.g. when the
    ///      lock window is shown by another trigger such as sleep/resume).
    /// </summary>
    public sealed class ReLockService : IDisposable
    {
        // ------------------------------------------------------------------ //
        //  Events                                                             //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Raised every second during the warning period.
        /// The argument is the number of seconds remaining until re-lock.
        /// Always raised on a background thread — callers must marshal to UI.
        /// </summary>
        public event EventHandler<int> WarningTick;

        /// <summary>
        /// Raised once when the countdown reaches zero.
        /// Always raised on a background thread — callers must marshal to UI.
        /// </summary>
        public event EventHandler ReLockRequested;

        // ------------------------------------------------------------------ //
        //  Fields                                                             //
        // ------------------------------------------------------------------ //

        private readonly FirebaseService _firebase;
        private Timer _timer;
        private int _totalSeconds;
        private int _warnBeforeSeconds;
        private int _remainingSeconds;
        private bool _disposed;
        private readonly object _lock = new object();

        /// <summary>Default re-lock interval when neither Firebase nor App.config provides a value: 30 minutes.</summary>
        private const int DefaultReLockSeconds = 1800;

        // ------------------------------------------------------------------ //
        //  Constructor                                                        //
        // ------------------------------------------------------------------ //

        public ReLockService(FirebaseService firebase)
        {
            _firebase = firebase ?? throw new ArgumentNullException(nameof(firebase));
        }

        // ------------------------------------------------------------------ //
        //  Public API                                                         //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Reads the re-lock interval (Firebase → App.config fallback) and
        /// starts the countdown.  Does nothing if the resolved interval is 0.
        /// </summary>
        public async Task StartAsync(string machineId)
        {
            Cancel(); // ensure no lingering timer

            int intervalSeconds = 0;

            // ── 1. Try Firebase ───────────────────────────────────────────
            bool firebaseReachable = false;
            int? firebaseValue = null;
            try
            {
                firebaseReachable = await _firebase.IsAvailableAsync().ConfigureAwait(false);

                if (firebaseReachable)
                    firebaseValue = await _firebase
                        .GetReLockIntervalAsync(machineId)
                        .ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Logger.LogFirebaseError(ex, "ReLockService.StartAsync");
            }

            // firebaseValue == null  → field not set on Firebase → use fallback
            // firebaseValue == 0     → explicitly disabled on Firebase → stop here
            // firebaseValue  > 0     → use the Firebase value
            if (firebaseReachable && firebaseValue.HasValue)
            {
                intervalSeconds = firebaseValue.Value;
                if (intervalSeconds == 0)
                {
                    Logger.LogInfo("[ReLock] Re-lock disabled via Firebase (relock_after_seconds = 0).");
                    return;
                }
            }
            else
            {
                // ── 2. Fallback to App.config (default 1800s = 30 min) ────────
                string reason = !firebaseReachable
                    ? "Firebase unreachable"
                    : "Firebase field not set";

                string cfgValue = ConfigurationManager.AppSettings["ReLockAfterSeconds"];
                if (!int.TryParse(cfgValue, out intervalSeconds) || intervalSeconds < 0)
                    intervalSeconds = DefaultReLockSeconds;

                Logger.LogInfo(
                    $"[ReLock] {reason} — using App.config fallback: {intervalSeconds}s");
            }

            // ── 3. Disabled? ──────────────────────────────────────────────
            if (intervalSeconds <= 0)
            {
                Logger.LogInfo("[ReLock] Re-lock is disabled (interval = 0).");
                return;
            }

            // ── 4. Read warn-before threshold ─────────────────────────────
            string warnCfg = ConfigurationManager.AppSettings["ReLockWarnBeforeSeconds"];
            if (!int.TryParse(warnCfg, out _warnBeforeSeconds) || _warnBeforeSeconds < 0)
                _warnBeforeSeconds = 30;

            // Clamp: warning cannot exceed total interval
            if (_warnBeforeSeconds > intervalSeconds)
                _warnBeforeSeconds = intervalSeconds;

            // ── 5. Start countdown ────────────────────────────────────────
            _totalSeconds = intervalSeconds;
            _remainingSeconds = intervalSeconds;

            Logger.LogInfo(
                $"[ReLock] Timer started: {_totalSeconds}s total, " +
                $"warning at {_warnBeforeSeconds}s before expiry.");

            lock (_lock)
            {
                _timer = new Timer(1000) { AutoReset = true };
                _timer.Elapsed += OnTimerElapsed;
                _timer.Start();
            }
        }

        /// <summary>
        /// Stops the countdown timer immediately. Safe to call multiple times.
        /// </summary>
        public void Cancel()
        {
            lock (_lock)
            {
                if (_timer != null)
                {
                    _timer.Stop();
                    _timer.Elapsed -= OnTimerElapsed;
                    _timer.Dispose();
                    _timer = null;
                    Logger.LogInfo("[ReLock] Timer cancelled.");
                }
            }
        }

        // ------------------------------------------------------------------ //
        //  Timer callback                                                     //
        // ------------------------------------------------------------------ //

        private void OnTimerElapsed(object sender, ElapsedEventArgs e)
        {
            int remaining = Interlocked.Decrement(ref _remainingSeconds);

            if (remaining <= 0)
            {
                // Time's up — stop timer and request re-lock
                Cancel();
                Logger.LogInfo("[ReLock] Countdown reached 0 — requesting re-lock.");
                ReLockRequested?.Invoke(this, EventArgs.Empty);
                return;
            }

            // Fire warning ticks during the warning window
            if (remaining <= _warnBeforeSeconds)
            {
                WarningTick?.Invoke(this, remaining);
            }
        }

        // ------------------------------------------------------------------ //
        //  IDisposable                                                        //
        // ------------------------------------------------------------------ //

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            Cancel();
        }
    }
}
