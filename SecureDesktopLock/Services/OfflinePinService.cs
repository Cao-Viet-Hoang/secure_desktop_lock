using SecureDesktopLock.Utils;
using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SecureDesktopLock.Services
{
    /// <summary>
    /// Manages the per-machine offline PIN and its remaining unlock count.
    ///
    /// The PIN is now fixed and set by the admin via the dashboard (no longer
    /// randomly rotated after each use).  Each successful PIN unlock decrements
    /// the count by one; when the count reaches zero the PIN is blocked.
    ///
    /// Sync strategy for unlock_count
    /// --------------------------------
    ///   Online unlock  : decrement Firebase directly, update local cache.
    ///   Offline unlock : decrement local cache, increment pending-decrements
    ///                    counter stored in <c>unlock_count.pending</c>.
    ///   On reconnect   : fetch Firebase count, subtract pending decrements,
    ///                    push result, clear pending file.
    ///                    Formula: new = max(0, firebase_count − pending)
    ///                    This correctly handles admin resets that happen while
    ///                    the machine is offline.
    /// </summary>
    public sealed class OfflinePinService
    {
        // ------------------------------------------------------------------ //
        //  File paths                                                         //
        // ------------------------------------------------------------------ //

        public static readonly string CachePath =
            Path.Combine(Logger.DataRoot, "offline_pin.dat");

        public static readonly string CountCachePath =
            Path.Combine(Logger.DataRoot, "unlock_count.dat");

        /// <summary>
        /// Stores how many PIN unlocks occurred while Firebase was unreachable.
        /// Cleared after the pending decrements are successfully synced.
        /// </summary>
        public static readonly string CountPendingPath =
            Path.Combine(Logger.DataRoot, "unlock_count.pending");

        private const int SeedMaxRetries = 3;
        private static readonly TimeSpan SeedRetryBaseDelay = TimeSpan.FromSeconds(5);

        // ------------------------------------------------------------------ //
        //  Dependencies                                                       //
        // ------------------------------------------------------------------ //

        private readonly FirebaseService _firebaseService;
        private readonly EncryptionService _encryptionService;

        public OfflinePinService(
            FirebaseService firebaseService,
            EncryptionService encryptionService)
        {
            _firebaseService = firebaseService
                ?? throw new ArgumentNullException(nameof(firebaseService));
            _encryptionService = encryptionService
                ?? throw new ArgumentNullException(nameof(encryptionService));
        }

        // ------------------------------------------------------------------ //
        //  Startup initialisation                                             //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Syncs PIN and unlock_count from Firebase to the local cache on startup.
        /// If pending offline decrements exist, they are pushed to Firebase first
        /// (so a reset by the admin is correctly factored in).
        ///
        /// Safe to call fire-and-forget — all errors are caught and logged.
        /// </summary>
        public async Task InitializeAsync(string machineId, CancellationToken ct = default)
        {
            for (int attempt = 1; attempt <= SeedMaxRetries; attempt++)
            {
                try
                {
                    Logger.LogInfo(
                        $"OfflinePinService.Initialize: attempt {attempt}/{SeedMaxRetries} for machineId={machineId}.");

                    if (!await _firebaseService.IsAvailableAsync(ct).ConfigureAwait(false))
                    {
                        Logger.LogWarning(
                            $"OfflinePinService.Initialize: Firebase unreachable on attempt {attempt}/{SeedMaxRetries}.");

                        if (attempt < SeedMaxRetries)
                        {
                            var delay = TimeSpan.FromTicks(SeedRetryBaseDelay.Ticks * (1 << (attempt - 1)));
                            Logger.LogInfo($"OfflinePinService.Initialize: retrying in {delay.TotalSeconds}s…");
                            await Task.Delay(delay, ct).ConfigureAwait(false);
                            continue;
                        }

                        Logger.LogError(
                            $"OfflinePinService.Initialize: all {SeedMaxRetries} attempts failed — staying offline.");
                        return;
                    }

                    // ── 1. Resolve pending count decrements ─────────────────
                    int pending = ReadPendingDecrements();
                    if (pending > 0)
                    {
                        Logger.LogInfo(
                            $"OfflinePinService.Initialize: {pending} pending decrement(s) found — syncing.");
                        try
                        {
                            int? firebaseCount = await _firebaseService
                                .GetUnlockCountAsync(machineId, ct)
                                .ConfigureAwait(false);

                            int resolved = firebaseCount.HasValue
                                ? Math.Max(0, firebaseCount.Value - pending)
                                : 0;

                            await _firebaseService
                                .SetUnlockCountAsync(machineId, resolved, ct)
                                .ConfigureAwait(false);

                            WriteCountCache(resolved);
                            ClearPendingDecrements();
                            Logger.LogInfo(
                                $"OfflinePinService.Initialize: pending decrements synced. " +
                                $"firebase={firebaseCount}, pending={pending}, resolved={resolved}.");
                        }
                        catch (Exception ex)
                        {
                            Logger.LogFirebaseError(ex, "OfflinePinService.Initialize.SyncPending");
                            if (attempt < SeedMaxRetries)
                            {
                                var d = TimeSpan.FromTicks(SeedRetryBaseDelay.Ticks * (1 << (attempt - 1)));
                                await Task.Delay(d, ct).ConfigureAwait(false);
                                continue;
                            }
                            return;
                        }
                    }

                    // ── 2. Pull PIN from Firebase ────────────────────────────
                    try
                    {
                        string pin = await _firebaseService
                            .GetOfflinePinAsync(machineId, ct)
                            .ConfigureAwait(false);

                        if (pin != null)
                        {
                            WriteCache(pin);
                            Logger.LogInfo($"OfflinePinService.Initialize: PIN cache refreshed for machineId={machineId}.");
                        }
                        else
                        {
                            Logger.LogWarning(
                                $"OfflinePinService.Initialize: no offline_pin set on Firebase for machineId={machineId}. " +
                                "Admin must configure a PIN via the dashboard.");
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.LogFirebaseError(ex, "OfflinePinService.Initialize.FetchPin");
                    }

                    // ── 3. Pull unlock_count from Firebase (if no pending) ───
                    if (pending == 0)
                    {
                        try
                        {
                            int? count = await _firebaseService
                                .GetUnlockCountAsync(machineId, ct)
                                .ConfigureAwait(false);

                            if (count.HasValue)
                            {
                                WriteCountCache(count.Value);
                                Logger.LogInfo(
                                    $"OfflinePinService.Initialize: unlock_count={count.Value} cached for machineId={machineId}.");
                            }
                            else
                            {
                                Logger.LogWarning(
                                    $"OfflinePinService.Initialize: no unlock_count set on Firebase for machineId={machineId}.");
                            }
                        }
                        catch (Exception ex)
                        {
                            Logger.LogFirebaseError(ex, "OfflinePinService.Initialize.FetchCount");
                        }
                    }

                    return; // success
                }
                catch (Exception ex)
                {
                    Logger.LogError(
                        $"OfflinePinService.Initialize: attempt {attempt}/{SeedMaxRetries} failed.", ex);

                    if (attempt < SeedMaxRetries)
                    {
                        var delay = TimeSpan.FromTicks(SeedRetryBaseDelay.Ticks * (1 << (attempt - 1)));
                        try { await Task.Delay(delay, ct).ConfigureAwait(false); }
                        catch (OperationCanceledException) { return; }
                    }
                }
            }
        }

        // ------------------------------------------------------------------ //
        //  Decrement on unlock                                                //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Synchronously decrements the local unlock-count cache by one and
        /// records a pending decrement.  Returns the new cached count, or -1 if
        /// the write failed.
        ///
        /// The pending file is written BEFORE the cache file.  If the process
        /// crashes between the two writes, startup will still see the pending
        /// decrement and reconcile via <see cref="FlushPendingDecrementsAsync"/>
        /// (otherwise the user would get a free unlock after restart because the
        /// authoritative Firebase value would overwrite the locally-decremented
        /// cache).
        /// </summary>
        public int DecrementLocalCache()
        {
            try
            {
                int? cached = ReadCachedCount();
                int newLocal = cached.HasValue ? Math.Max(0, cached.Value - 1) : 0;

                // pending FIRST — crash-safety invariant
                int pending = ReadPendingDecrements() + 1;
                WritePendingDecrements(pending);
                WriteCountCache(newLocal);

                Logger.LogInfo(
                    $"OfflinePinService.DecrementLocalCache: cache={newLocal}, pending={pending}.");
                return newLocal;
            }
            catch (Exception ex)
            {
                Logger.LogError("OfflinePinService.DecrementLocalCache: failed to write state.", ex);
                return -1;
            }
        }

        /// <summary>
        /// Pushes any pending offline decrements to Firebase.
        /// No-op if there are no pending decrements or Firebase is unreachable.
        /// On success the cache is updated to the resolved count and the
        /// pending file is cleared.
        /// </summary>
        public async Task FlushPendingDecrementsAsync(string machineId, CancellationToken ct = default)
        {
            int pending = ReadPendingDecrements();
            if (pending == 0) return;

            bool online = false;
            try
            {
                online = await _firebaseService.IsAvailableAsync(ct).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Logger.LogFirebaseError(ex, "OfflinePinService.Flush.IsAvailable");
            }

            if (!online)
            {
                Logger.LogInfo(
                    $"OfflinePinService.Flush: Firebase unavailable; {pending} decrement(s) deferred.");
                return;
            }

            try
            {
                int? firebaseCount = await _firebaseService
                    .GetUnlockCountAsync(machineId, ct)
                    .ConfigureAwait(false);

                int resolved = firebaseCount.HasValue
                    ? Math.Max(0, firebaseCount.Value - pending)
                    : 0;

                await _firebaseService
                    .SetUnlockCountAsync(machineId, resolved, ct)
                    .ConfigureAwait(false);

                WriteCountCache(resolved);
                ClearPendingDecrements();

                Logger.LogInfo(
                    $"OfflinePinService.Flush: synced {pending} decrement(s). " +
                    $"firebase={firebaseCount}, resolved={resolved}, machineId={machineId}.");
            }
            catch (Exception ex)
            {
                Logger.LogFirebaseError(ex, "OfflinePinService.Flush");
            }
        }

        /// <summary>True when there are unsynced offline decrements on disk.</summary>
        public bool HasPendingDecrements() => ReadPendingDecrements() > 0;

        // ------------------------------------------------------------------ //
        //  PIN cache I/O                                                      //
        // ------------------------------------------------------------------ //

        public string ReadCachedPin()
        {
            try
            {
                if (!File.Exists(CachePath)) return null;
                string blob = File.ReadAllText(CachePath, Encoding.UTF8).Trim();
                return string.IsNullOrEmpty(blob) ? null : blob;
            }
            catch (Exception ex)
            {
                Logger.LogError("Failed to read offline_pin cache.", ex);
                return null;
            }
        }

        public void WriteCache(string encryptedBlob)
        {
            EnsureDir();
            File.WriteAllText(CachePath, encryptedBlob, Encoding.UTF8);
        }

        // ------------------------------------------------------------------ //
        //  Count cache I/O                                                    //
        // ------------------------------------------------------------------ //

        public int? ReadCachedCount()
        {
            try
            {
                if (!File.Exists(CountCachePath)) return null;
                string text = File.ReadAllText(CountCachePath, Encoding.UTF8).Trim();
                if (int.TryParse(text, out int val)) return val;
                return null;
            }
            catch (Exception ex)
            {
                Logger.LogError("Failed to read unlock_count cache.", ex);
                return null;
            }
        }

        public void WriteCountCache(int count)
        {
            try
            {
                EnsureDir();
                File.WriteAllText(CountCachePath, count.ToString(), Encoding.UTF8);
            }
            catch (Exception ex)
            {
                Logger.LogError("Failed to write unlock_count cache.", ex);
            }
        }

        // ------------------------------------------------------------------ //
        //  Pending-decrements I/O                                             //
        // ------------------------------------------------------------------ //

        private int ReadPendingDecrements()
        {
            try
            {
                if (!File.Exists(CountPendingPath)) return 0;
                string text = File.ReadAllText(CountPendingPath, Encoding.UTF8).Trim();
                return int.TryParse(text, out int val) ? Math.Max(0, val) : 0;
            }
            catch (Exception ex)
            {
                Logger.LogError("Failed to read unlock_count.pending.", ex);
                return 0;
            }
        }

        private void WritePendingDecrements(int count)
        {
            EnsureDir();
            File.WriteAllText(CountPendingPath, count.ToString(), Encoding.UTF8);
        }

        private void ClearPendingDecrements()
        {
            try
            {
                if (File.Exists(CountPendingPath))
                    File.Delete(CountPendingPath);
            }
            catch (Exception ex)
            {
                Logger.LogError("Failed to delete unlock_count.pending.", ex);
            }
        }

        // ------------------------------------------------------------------ //
        //  Helpers                                                            //
        // ------------------------------------------------------------------ //

        private static void EnsureDir()
        {
            string dir = Path.GetDirectoryName(CachePath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                Directory.CreateDirectory(dir);
        }
    }
}
