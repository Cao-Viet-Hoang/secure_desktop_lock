using SecureDesktopLock.Utils;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SecureDesktopLock.Services
{
    /// <summary>
    /// Manages the per-machine offline PIN — the only password the user can
    /// type on the lock screen.  Used as an emergency fallback when Firebase
    /// is unreachable and the admin remote-unlock command cannot be delivered.
    ///
    /// Lifecycle
    /// ---------
    ///   • Seeded on first boot if Firebase has no <c>offline_pin</c> node.
    ///   • Synced from Firebase to the local cache on every successful fetch.
    ///   • Rotated only when the user successfully types it (single-use after
    ///     each consumption).
    ///
    /// Conflict resolution (offline rotation)
    /// --------------------------------------
    ///   When the user unlocks with the PIN while Firebase is unreachable,
    ///   a new PIN is generated and written to the cache, plus a
    ///   <c>offline_pin.pending</c> flag file.  On the next successful Firebase
    ///   reach (boot or first network call), the pending PIN is pushed up
    ///   BEFORE any pull, so the local rotation is never overwritten by the
    ///   stale Firebase value.
    /// </summary>
    public sealed class OfflinePinService
    {
        // ------------------------------------------------------------------ //
        //  Configuration                                                      //
        // ------------------------------------------------------------------ //

        public const int PinLength = 6;
        private const string CharPool = "0123456789";

        /// <summary>Cache file containing the encrypted offline PIN.</summary>
        public static readonly string CachePath =
            Path.Combine(Logger.DataRoot, "offline_pin.dat");

        /// <summary>Pending-sync marker.  Holds the rotated PIN that has not
        /// yet been pushed to Firebase.  Existence implies a sync is needed.</summary>
        public static readonly string PendingPath =
            Path.Combine(Logger.DataRoot, "offline_pin.pending");

        /// <summary>Maximum number of retry attempts for the initial seed.</summary>
        private const int SeedMaxRetries = 3;

        /// <summary>Delay between seed retries (doubles each attempt).</summary>
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
        //  Public API                                                         //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Generates a new PIN, pushes it to Firebase, and writes the cache.
        /// Called immediately after a successful offline-PIN unlock so each
        /// PIN is single-use.
        ///
        /// If Firebase is unreachable, the new PIN is still cached locally
        /// and a <c>pending</c> marker is written so the next online run
        /// pushes the rotation up before pulling.
        /// </summary>
        public async Task RotateAsync(string machineId, CancellationToken ct = default)
        {
            string newPin = GenerateSecurePin();
            string encrypted = _encryptionService.Encrypt(newPin);

            bool savedRemotely = false;

            try
            {
                await _firebaseService
                    .SetOfflinePinAsync(machineId, encrypted, ct)
                    .ConfigureAwait(false);
                savedRemotely = true;
            }
            catch (Exception ex)
            {
                Logger.LogFirebaseError(ex, "OfflinePinService.RotateAsync.Upload");
            }

            // Always write cache (authoritative for local unlock until next sync).
            try
            {
                WriteCache(encrypted);
            }
            catch (Exception ex)
            {
                Logger.LogError("Failed to write offline_pin cache.", ex);
            }

            // If Firebase failed, mark pending so we push on next successful reach.
            if (!savedRemotely)
            {
                try
                {
                    WritePending(encrypted);
                    Logger.LogWarning(
                        $"Offline PIN rotated locally but NOT pushed to Firebase. " +
                        $"Pending sync queued. machineId={machineId}");
                }
                catch (Exception ex)
                {
                    Logger.LogError("Failed to write offline_pin pending marker.", ex);
                }
            }
            else
            {
                ClearPending();
                Logger.LogInfo($"Offline PIN rotated successfully for machineId={machineId}");
            }
        }

        /// <summary>
        /// Ensures Firebase has an <c>offline_pin</c> for this machine.  If a
        /// pending local rotation exists from a previous offline unlock, push
        /// it up FIRST so the latest local value wins. Then, if Firebase still
        /// has no value, seed a fresh PIN.
        ///
        /// Safe to call fire-and-forget — all errors are caught and logged.
        /// </summary>
        public async Task EnsurePinExistsAsync(string machineId, CancellationToken ct = default)
        {
            for (int attempt = 1; attempt <= SeedMaxRetries; attempt++)
            {
                try
                {
                    Logger.LogInfo(
                        $"EnsurePinExists: attempt {attempt}/{SeedMaxRetries} for machineId={machineId}.");

                    if (!await _firebaseService.IsAvailableAsync(ct).ConfigureAwait(false))
                    {
                        Logger.LogWarning(
                            $"EnsurePinExists: Firebase unreachable on attempt {attempt}/{SeedMaxRetries}.");

                        if (attempt < SeedMaxRetries)
                        {
                            var delay = TimeSpan.FromTicks(SeedRetryBaseDelay.Ticks * (1 << (attempt - 1)));
                            Logger.LogInfo($"EnsurePinExists: retrying in {delay.TotalSeconds}s…");
                            await Task.Delay(delay, ct).ConfigureAwait(false);
                            continue;
                        }

                        Logger.LogError(
                            $"EnsurePinExists: all {SeedMaxRetries} attempts failed — Firebase unreachable.");
                        return;
                    }

                    // ── 1. Push any pending rotation BEFORE pulling ─────────
                    string pending = ReadPending();
                    if (pending != null)
                    {
                        Logger.LogInfo(
                            $"EnsurePinExists: pending offline rotation found — pushing to Firebase.");
                        try
                        {
                            await _firebaseService
                                .SetOfflinePinAsync(machineId, pending, ct)
                                .ConfigureAwait(false);
                            ClearPending();
                            // Cache is already up-to-date with the pending value.
                            Logger.LogInfo("EnsurePinExists: pending rotation synced.");
                            return;
                        }
                        catch (Exception ex)
                        {
                            Logger.LogFirebaseError(ex, "EnsurePinExists.PushPending");
                            // Fall through and retry on next attempt.
                            if (attempt < SeedMaxRetries)
                            {
                                var d = TimeSpan.FromTicks(SeedRetryBaseDelay.Ticks * (1 << (attempt - 1)));
                                await Task.Delay(d, ct).ConfigureAwait(false);
                                continue;
                            }
                            return;
                        }
                    }

                    // ── 2. Seed if Firebase has nothing ─────────────────────
                    string existing = await _firebaseService
                        .GetOfflinePinAsync(machineId, ct)
                        .ConfigureAwait(false);

                    if (existing != null)
                    {
                        Logger.LogInfo(
                            $"EnsurePinExists: offline PIN already exists for machineId={machineId}.");
                        // Refresh local cache from Firebase.
                        WriteCache(existing);
                    }
                    else
                    {
                        Logger.LogInfo(
                            $"EnsurePinExists: no offline PIN for machineId={machineId} — auto-seeding.");

                        string newPin = GenerateSecurePin();
                        string stored = _encryptionService.Encrypt(newPin);

                        await _firebaseService
                            .SetOfflinePinAsync(machineId, stored, ct)
                            .ConfigureAwait(false);

                        WriteCache(stored);

                        Logger.LogInfo(
                            $"EnsurePinExists: auto-seeded offline PIN for machineId={machineId}. " +
                            $"PIN (plaintext): {newPin}");
                    }

                    return; // Success
                }
                catch (Exception ex)
                {
                    Logger.LogError(
                        $"EnsurePinExists: attempt {attempt}/{SeedMaxRetries} failed.", ex);

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
        //  Cache I/O                                                          //
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
        //  Pending-sync marker                                                //
        // ------------------------------------------------------------------ //

        private static string ReadPending()
        {
            try
            {
                if (!File.Exists(PendingPath)) return null;
                string blob = File.ReadAllText(PendingPath, Encoding.UTF8).Trim();
                return string.IsNullOrEmpty(blob) ? null : blob;
            }
            catch (Exception ex)
            {
                Logger.LogError("Failed to read offline_pin.pending.", ex);
                return null;
            }
        }

        private static void WritePending(string encryptedBlob)
        {
            EnsureDir();
            File.WriteAllText(PendingPath, encryptedBlob, Encoding.UTF8);
        }

        private static void ClearPending()
        {
            try
            {
                if (File.Exists(PendingPath))
                    File.Delete(PendingPath);
            }
            catch (Exception ex)
            {
                Logger.LogError("Failed to delete offline_pin.pending.", ex);
            }
        }

        // ------------------------------------------------------------------ //
        //  PIN generation                                                     //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Cryptographically random numeric PIN of <see cref="PinLength"/>
        /// digits, drawn via rejection sampling from <see cref="CharPool"/>
        /// to avoid modulo bias.
        /// </summary>
        public static string GenerateSecurePin()
        {
            int poolLen = CharPool.Length;
            int maxValue = byte.MaxValue - (byte.MaxValue % poolLen) - 1;
            var result = new StringBuilder(PinLength);
            var rng = new RNGCryptoServiceProvider();
            byte[] buffer = new byte[1];

            while (result.Length < PinLength)
            {
                rng.GetBytes(buffer);
                if (buffer[0] <= maxValue)
                    result.Append(CharPool[buffer[0] % poolLen]);
            }

            return result.ToString();
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
