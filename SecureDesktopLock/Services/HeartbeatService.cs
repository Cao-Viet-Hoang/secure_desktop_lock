using SecureDesktopLock.Utils;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace SecureDesktopLock.Services
{
    /// <summary>
    /// Periodically writes <c>last_seen</c> for this machine so the admin
    /// dashboard knows the lock is alive and reachable.
    ///
    /// Lifecycle
    /// ---------
    ///   • Started together with <see cref="UnlockCommandService"/> when the
    ///     lock window appears.  Stopped on unlock.
    ///   • Tick interval: 30 seconds (dashboard treats &lt;60s as online).
    ///
    /// Semantics
    /// ---------
    ///   "online" on the dashboard means "this machine is currently locked
    ///   and accepting unlock commands".  Once unlocked, the heartbeat stops
    ///   and the dashboard shows the machine as offline — clicking "Unlock"
    ///   would be a no-op anyway, so this avoids confusion.
    /// </summary>
    public sealed class HeartbeatService : IDisposable
    {
        private static readonly TimeSpan Interval = TimeSpan.FromSeconds(30);

        private readonly FirebaseService _firebase;
        private readonly string _machineId;
        private CancellationTokenSource _cts;
        private Task _loop;
        private readonly object _lock = new object();

        public HeartbeatService(FirebaseService firebase, string machineId)
        {
            _firebase = firebase ?? throw new ArgumentNullException(nameof(firebase));
            _machineId = machineId ?? throw new ArgumentNullException(nameof(machineId));
        }

        public void Start()
        {
            lock (_lock)
            {
                if (_loop != null && !_loop.IsCompleted) return;

                _cts = new CancellationTokenSource();
                _loop = Task.Run(() => RunAsync(_cts.Token));
                Logger.LogInfo("[Heartbeat] Started.");
            }
        }

        public void Stop()
        {
            lock (_lock)
            {
                if (_cts == null) return;
                try { _cts.Cancel(); }
                catch (ObjectDisposedException) { }
                _cts.Dispose();
                _cts = null;
                Logger.LogInfo("[Heartbeat] Stopped.");
            }

            // Clear last_seen so the dashboard shows offline immediately
            // instead of waiting up to 60 s for the timestamp to go stale.
            _ = Task.Run(async () =>
            {
                try { await _firebase.ClearLastSeenAsync(_machineId).ConfigureAwait(false); }
                catch (Exception ex) { Logger.LogError("[Heartbeat] ClearLastSeen failed.", ex); }
            });
        }

        public void Dispose() => Stop();

        private async Task RunAsync(CancellationToken ct)
        {
            // Send an immediate beat so the dashboard sees us right away.
            try
            {
                await _firebase.SetLastSeenAsync(_machineId, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { return; }
            catch (Exception ex)
            {
                Logger.LogError("[Heartbeat] Initial beat failed.", ex);
            }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(Interval, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }

                try
                {
                    await _firebase.SetLastSeenAsync(_machineId, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                catch (Exception ex)
                {
                    Logger.LogError("[Heartbeat] Beat failed.", ex);
                }
            }
        }
    }
}
