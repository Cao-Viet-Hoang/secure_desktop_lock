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
    /// Generates cryptographically secure random passwords and rotates them
    /// in Firebase Realtime Database after each successful unlock.
    ///
    /// Password policy
    /// ---------------
    ///   • Length       : 6 digits (configurable via <see cref="PasswordLength"/>)
    ///   • Character set: digits only (numeric PIN-style)
    ///   • Source       : <see cref="RNGCryptoServiceProvider"/> (CSPRNG)
    ///
    /// Rotation flow
    /// -------------
    ///   1. Generate a new password.
    ///   2. Pass through <see cref="EncryptionService"/> (currently no-op / plaintext).
    ///   3. Store the value in Firebase Realtime Database (primary).
    ///   4. Store the value in the local offline cache (backup).
    ///   5. Log success or failure.
    ///
    /// Offline cache
    /// -------------
    ///   %ProgramData%\SecureLock\cache.dat
    ///
    ///   The cache file contains the password in plaintext.
    ///   It is read when Firebase is unreachable (offline mode).
    /// </summary>
    public sealed class PasswordRotationService
    {
        // ------------------------------------------------------------------ //
        //  Configuration constants                                            //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Number of digits in a generated password.
        /// Change this single value to adjust password length.
        /// </summary>
        public const int PasswordLength = 6;

        /// <summary>
        /// Character pool — digits only for a numeric PIN-style password.
        /// </summary>
        private const string CharPool = "0123456789";

        // ------------------------------------------------------------------ //
        //  Cache path                                                         //
        // ------------------------------------------------------------------ //

        /// <summary>Full path to the local offline password cache file.</summary>
        public static readonly string CachePath =
            Path.Combine(Logger.DataRoot, "cache.dat");

        // ------------------------------------------------------------------ //
        //  Dependencies                                                       //
        // ------------------------------------------------------------------ //

        private readonly FirebaseService _firebaseService;
        private readonly EncryptionService _encryptionService;

        // ------------------------------------------------------------------ //
        //  Constructor                                                        //
        // ------------------------------------------------------------------ //

        public PasswordRotationService(
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
        /// Generates a new secure password, encrypts it and pushes it to both
        /// Firebase and the local cache.
        ///
        /// This method is called immediately after a successful unlock so that
        /// each unlock session uses a unique one-time password (OTP-like flow).
        ///
        /// Failures are logged but do NOT propagate — the unlock
        /// has already succeeded and we must not disrupt the user session.
        /// </summary>
        public async Task RotateAsync(
            string machineId,
            CancellationToken ct = default)
        {
            string newPassword = GenerateSecurePassword();
            string encrypted = _encryptionService.Encrypt(newPassword);

            bool savedRemotely = false;
            bool savedLocally = false;

            // 1. Upload to Firebase
            try
            {
                await _firebaseService
                    .SetPasswordAsync(machineId, encrypted, ct)
                    .ConfigureAwait(false);
                savedRemotely = true;
            }
            catch (Exception ex)
            {
                Logger.LogFirebaseError(ex, "PasswordRotation.UploadToFirebase");
            }

            // 2. Write to local cache (always attempt, independently of Firebase)
            try
            {
                WriteCache(encrypted);
                savedLocally = true;
            }
            catch (Exception ex)
            {
                Logger.LogError("Failed to write local password cache.", ex);
            }

            if (savedRemotely && savedLocally)
                Logger.LogInfo($"Password rotated successfully for machineId={machineId}");
            else if (savedLocally)
                Logger.LogWarning(
                    $"Password cached locally but NOT uploaded to Firebase. machineId={machineId}");
            else
                Logger.LogError(
                    $"Password rotation FAILED (no save target succeeded). machineId={machineId}");
        }

        /// <summary>
        /// Checks whether a password already exists for <paramref name="machineId"/> in
        /// Firebase. If no record is found (first run on this machine), generates a new
        /// password, uploads it to Firebase and writes it to the local cache.
        ///
        /// Safe to call fire-and-forget — all errors are caught and logged; nothing
        /// propagates to the caller.
        ///
        /// Because encryption is currently disabled, the generated password is written
        /// to the log so the administrator can retrieve it.
        /// </summary>
        /// <summary>Maximum number of retry attempts for the initial seed.</summary>
        private const int SeedMaxRetries = 3;

        /// <summary>Delay between seed retries (doubles each attempt).</summary>
        private static readonly TimeSpan SeedRetryBaseDelay = TimeSpan.FromSeconds(5);

        public async Task EnsurePasswordExistsAsync(
            string machineId,
            CancellationToken ct = default)
        {
            for (int attempt = 1; attempt <= SeedMaxRetries; attempt++)
            {
                try
                {
                    Logger.LogInfo(
                        $"EnsurePasswordExists: attempt {attempt}/{SeedMaxRetries} for machineId={machineId}.");

                    // Only worth checking if Firebase is reachable
                    if (!await _firebaseService.IsAvailableAsync(ct).ConfigureAwait(false))
                    {
                        Logger.LogWarning(
                            $"EnsurePasswordExists: Firebase unreachable on attempt {attempt}/{SeedMaxRetries}. " +
                            "Check the log above for detailed error from IsAvailableAsync.");

                        if (attempt < SeedMaxRetries)
                        {
                            var delay = TimeSpan.FromTicks(SeedRetryBaseDelay.Ticks * (1 << (attempt - 1)));
                            Logger.LogInfo($"EnsurePasswordExists: retrying in {delay.TotalSeconds}s…");
                            await Task.Delay(delay, ct).ConfigureAwait(false);
                            continue;
                        }

                        Logger.LogError(
                            $"EnsurePasswordExists: all {SeedMaxRetries} attempts failed — Firebase remained unreachable. " +
                            "Verify your firebase_config.json credentials and network connectivity.");
                        return;
                    }

                    string existing = await _firebaseService
                        .GetPasswordAsync(machineId, ct)
                        .ConfigureAwait(false);

                    if (existing != null)
                    {
                        Logger.LogInfo(
                            $"EnsurePasswordExists: password already exists for machineId={machineId}.");
                        return;
                    }

                    // No password found — generate and seed
                    Logger.LogInfo(
                        $"EnsurePasswordExists: no record found for machineId={machineId} — auto-seeding.");

                    string newPassword = GenerateSecurePassword();
                    string stored = _encryptionService.Encrypt(newPassword);

                    await _firebaseService
                        .SetPasswordAsync(machineId, stored, ct)
                        .ConfigureAwait(false);

                    WriteCache(stored);

                    // Log the plaintext password so the administrator can retrieve it.
                    // Remove this log line once encryption is enabled.
                    Logger.LogInfo(
                        $"EnsurePasswordExists: auto-seeded password for machineId={machineId}. " +
                        $"Password (plaintext): {newPassword}");
                    return; // Success — exit the retry loop
                }
                catch (Exception ex)
                {
                    Logger.LogError(
                        $"EnsurePasswordExists: attempt {attempt}/{SeedMaxRetries} failed.", ex);

                    if (attempt < SeedMaxRetries)
                    {
                        var delay = TimeSpan.FromTicks(SeedRetryBaseDelay.Ticks * (1 << (attempt - 1)));
                        Logger.LogInfo($"EnsurePasswordExists: retrying in {delay.TotalSeconds}s…");
                        try { await Task.Delay(delay, ct).ConfigureAwait(false); }
                        catch (OperationCanceledException) { return; }
                    }
                    else
                    {
                        Logger.LogError(
                            $"EnsurePasswordExists: all {SeedMaxRetries} attempts exhausted for machineId={machineId}.");
                    }
                }
            }
        }

        /// <summary>
        /// Retrieves the password from the local offline cache.
        /// Returns <c>null</c> when the cache file does not exist or is empty.
        /// </summary>
        public string ReadCachedPassword()
        {
            try
            {
                if (!File.Exists(CachePath)) return null;
                string blob = File.ReadAllText(CachePath, Encoding.UTF8).Trim();
                return string.IsNullOrEmpty(blob) ? null : blob;
            }
            catch (Exception ex)
            {
                Logger.LogError("Failed to read local password cache.", ex);
                return null;
            }
        }

        /// <summary>
        /// Writes the password to the local offline cache.
        /// Creates the parent directory automatically.
        /// </summary>
        public void WriteCache(string encryptedBlob)
        {
            EnsureCacheDir();
            File.WriteAllText(CachePath, encryptedBlob, Encoding.UTF8);
        }

        // ------------------------------------------------------------------ //
        //  Password generation                                                //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Generates a cryptographically random password of length
        /// <see cref="PasswordLength"/> drawn from <see cref="CharPool"/>.
        ///
        /// Uses rejection sampling to eliminate modulo bias: characters are
        /// accepted only when the random byte falls within a range that divides
        /// <see cref="CharPool"/>.Length evenly.
        /// </summary>
        public static string GenerateSecurePassword()
        {
            int poolLen = CharPool.Length;
            int maxValue = byte.MaxValue - (byte.MaxValue % poolLen) - 1;
            var result = new StringBuilder(PasswordLength);
            var rng = new RNGCryptoServiceProvider();
            byte[] buffer = new byte[1];

            while (result.Length < PasswordLength)
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

        private static void EnsureCacheDir()
        {
            string dir = Path.GetDirectoryName(CachePath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                Directory.CreateDirectory(dir);
        }
    }
}
