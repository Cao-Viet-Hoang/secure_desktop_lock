using SecureDesktopLock.Utils;
using System;
using System.Collections.Generic;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;

namespace SecureDesktopLock.Services
{
    /// <summary>
    /// Polls Firebase for an admin-issued <c>unlock_request</c> for this
    /// machine.  When a valid (non-expired, unseen) command is found, deletes
    /// the node atomically and raises <see cref="UnlockRequested"/> so the
    /// LockWindow can close.
    ///
    /// Lifecycle
    /// ---------
    ///   • Started by App.xaml.cs whenever the lock window is shown.
    ///   • Stopped when the lock window is closed (no command means anything
    ///     while the screen is unlocked).
    ///   • Polling interval: 3 seconds (balance between latency and
    ///     Firebase request volume).
    ///
    /// Idempotency
    /// -----------
    ///   Tokens recently consumed are remembered in-memory for 5 minutes
    ///   so a delayed-DELETE / network blip cannot retrigger a stale unlock.
    /// </summary>
    public sealed class UnlockCommandService : IDisposable
    {
        // ------------------------------------------------------------------ //
        //  Configuration                                                      //
        // ------------------------------------------------------------------ //

        private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(3);
        private static readonly TimeSpan TokenMemoryWindow = TimeSpan.FromMinutes(10);
        private static readonly TimeSpan NetworkProbeInterval = TimeSpan.FromSeconds(2);

        // ------------------------------------------------------------------ //
        //  Events                                                             //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Raised on a background thread when a valid unlock command is
        /// consumed.  Subscribers must marshal to the UI thread.
        /// </summary>
        public event EventHandler UnlockRequested;

        // ------------------------------------------------------------------ //
        //  Fields                                                             //
        // ------------------------------------------------------------------ //

        private readonly FirebaseService _firebase;
        private readonly string _machineId;
        private CancellationTokenSource _cts;
        private Task _pollLoop;
        private readonly object _lock = new object();

        /// <summary>token → consumed-at-utc, expired entries pruned periodically.</summary>
        private readonly Dictionary<string, DateTimeOffset> _consumedTokens
            = new Dictionary<string, DateTimeOffset>(StringComparer.Ordinal);

        // ------------------------------------------------------------------ //
        //  Constructor                                                        //
        // ------------------------------------------------------------------ //

        public UnlockCommandService(FirebaseService firebase, string machineId)
        {
            _firebase = firebase ?? throw new ArgumentNullException(nameof(firebase));
            _machineId = machineId ?? throw new ArgumentNullException(nameof(machineId));
        }

        // ------------------------------------------------------------------ //
        //  Public API                                                         //
        // ------------------------------------------------------------------ //

        /// <summary>Begins polling.  Idempotent — calling twice is a no-op.</summary>
        public void Start()
        {
            lock (_lock)
            {
                if (_pollLoop != null && !_pollLoop.IsCompleted) return;

                _cts = new CancellationTokenSource();
                _pollLoop = Task.Run(() => PollLoopAsync(_cts.Token));
                Logger.LogInfo("[UnlockCommand] Polling started.");
            }
        }

        /// <summary>Stops polling.  Safe to call multiple times.</summary>
        public void Stop()
        {
            lock (_lock)
            {
                if (_cts == null) return;
                try { _cts.Cancel(); }
                catch (ObjectDisposedException) { }
                _cts.Dispose();
                _cts = null;
                Logger.LogInfo("[UnlockCommand] Polling stopped.");
            }
        }

        public void Dispose() => Stop();

        // ------------------------------------------------------------------ //
        //  Polling loop                                                       //
        // ------------------------------------------------------------------ //

        private async Task PollLoopAsync(CancellationToken ct)
        {
            // After sleep/resume the network adapter often takes a few seconds
            // to come back. Skip polling until the OS reports a network is up
            // so we don't spam the log with DNS-resolution failures.
            await WaitForNetworkAsync(ct).ConfigureAwait(false);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await CheckOnceAsync(ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                catch (Exception ex)
                {
                    Logger.LogError("[UnlockCommand] Poll iteration failed.", ex);
                }

                try
                {
                    await Task.Delay(PollInterval, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
            }
        }

        private static async Task WaitForNetworkAsync(CancellationToken ct)
        {
            if (NetworkInterface.GetIsNetworkAvailable()) return;

            Logger.LogInfo("[UnlockCommand] Waiting for network to become available…");
            while (!ct.IsCancellationRequested && !NetworkInterface.GetIsNetworkAvailable())
            {
                try { await Task.Delay(NetworkProbeInterval, ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { return; }
            }
            if (!ct.IsCancellationRequested)
                Logger.LogInfo("[UnlockCommand] Network available — beginning polling.");
        }

        private async Task CheckOnceAsync(CancellationToken ct)
        {
            var req = await _firebase.GetUnlockRequestAsync(_machineId, ct)
                .ConfigureAwait(false);

            if (req == null) return;

            // Already processed this token recently?
            PruneConsumedTokens();
            lock (_consumedTokens)
            {
                if (_consumedTokens.ContainsKey(req.Token))
                {
                    Logger.LogInfo($"[UnlockCommand] Ignoring already-consumed token.");
                    return;
                }
            }

            // Expired?
            if (req.IsExpired())
            {
                Logger.LogInfo(
                    $"[UnlockCommand] Ignoring expired token (expires_at={req.ExpiresAt}).");
                // Best-effort cleanup so the dashboard doesn't keep showing it.
                await _firebase.DeleteUnlockRequestAsync(_machineId, ct)
                    .ConfigureAwait(false);
                return;
            }

            // Valid — consume it.
            lock (_consumedTokens)
            {
                _consumedTokens[req.Token] = DateTimeOffset.UtcNow;
            }

            await _firebase.DeleteUnlockRequestAsync(_machineId, ct)
                .ConfigureAwait(false);

            Logger.LogInfo(
                $"[UnlockCommand] Valid unlock command received (issued_at={req.IssuedAt}).");

            UnlockRequested?.Invoke(this, EventArgs.Empty);
        }

        private void PruneConsumedTokens()
        {
            DateTimeOffset cutoff = DateTimeOffset.UtcNow - TokenMemoryWindow;
            lock (_consumedTokens)
            {
                List<string> stale = null;
                foreach (var kv in _consumedTokens)
                {
                    if (kv.Value < cutoff)
                    {
                        if (stale == null) stale = new List<string>();
                        stale.Add(kv.Key);
                    }
                }
                if (stale != null)
                    foreach (var key in stale) _consumedTokens.Remove(key);
            }
        }
    }
}
