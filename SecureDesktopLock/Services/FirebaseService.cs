using FireSharp;
using FireSharp.Config;
using FireSharp.Interfaces;
using Newtonsoft.Json;
using SecureDesktopLock.Utils;
using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SecureDesktopLock.Services
{
    /// <summary>
    /// Communicates with Google Firebase Realtime Database using the
    /// <c>FireSharp</c> library.
    ///
    /// Realtime Database layout
    /// ------------------------
    ///   machines/{machineId}/offline_pin            : string  (rotated when typed by user)
    ///   machines/{machineId}/unlock_request         : object  (single-use admin command)
    ///       ├── token                               : string  (32 hex random)
    ///       ├── issued_at                           : string  (ISO-8601 GMT+7)
    ///       └── expires_at                          : string  (ISO-8601 GMT+7)
    ///   machines/{machineId}/last_seen              : string  (heartbeat ISO-8601 GMT+7)
    ///   machines/{machineId}/relock_after_seconds   : int
    ///   machines/{machineId}/last_updated           : string  (ISO-8601 GMT+7)
    /// </summary>
    public class FirebaseService : IDisposable
    {
        private readonly IFirebaseClient _client;
        private bool _disposed;

        public FirebaseService(IFirebaseClient client)
        {
            _client = client ?? throw new ArgumentNullException(nameof(client));
        }

        /// <summary>Internal constructor used only by subclasses (e.g. null-object stubs).</summary>
        protected FirebaseService() { }

        /// <summary>
        /// Loads the Firebase configuration from the path stored in App.config
        /// key "FirebaseConfigPath", then creates and returns a service backed by FireSharp.
        /// </summary>
        public static FirebaseService CreateFromConfigFile()
        {
            string path = System.Configuration.ConfigurationManager
                .AppSettings["FirebaseConfigPath"];

            if (string.IsNullOrWhiteSpace(path))
                throw new InvalidOperationException(
                    "App.config key 'FirebaseConfigPath' is not set.");

            if (!Path.IsPathRooted(path))
                path = Path.GetFullPath(Path.Combine(
                    AppDomain.CurrentDomain.BaseDirectory, path));

            if (!File.Exists(path))
                throw new FileNotFoundException(
                    $"Firebase config file not found: {path}", path);

            string json = File.ReadAllText(path, Encoding.UTF8);
            FirebaseConfigFile cfg = JsonConvert.DeserializeObject<FirebaseConfigFile>(json);

            if (cfg == null || string.IsNullOrWhiteSpace(cfg.BasePath))
                throw new InvalidOperationException(
                    "Firebase config file is missing the 'base_path' field.");

            if (string.IsNullOrWhiteSpace(cfg.AuthSecret))
                throw new InvalidOperationException(
                    "Firebase config file is missing the 'auth_secret' field.");

            IFirebaseConfig config = new FirebaseConfig
            {
                BasePath = cfg.BasePath,
                AuthSecret = cfg.AuthSecret
            };

            IFirebaseClient client = new FirebaseClient(config);
            Logger.LogInfo($"FireSharp client created for base path '{cfg.BasePath}'.");
            return new FirebaseService(client);
        }

        // ------------------------------------------------------------------ //
        //  Offline PIN                                                        //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Fetches the offline PIN for this machine. Returns <c>null</c> when not set.
        /// </summary>
        public virtual async Task<string> GetOfflinePinAsync(
            string machineId,
            CancellationToken ct = default)
        {
            try
            {
                var response = await _client
                    .GetAsync($"machines/{machineId}/offline_pin")
                    .ConfigureAwait(false);

                if (response?.Body == null || response.Body == "null")
                {
                    Logger.LogInfo($"[FireSharp] Node machines/{machineId}/offline_pin does not exist.");
                    return null;
                }

                return response.ResultAs<string>();
            }
            catch (Exception ex)
            {
                Logger.LogFirebaseError(ex, "FirebaseService.GetOfflinePinAsync");
                throw;
            }
        }

        /// <summary>
        /// Writes the offline PIN for this machine.
        /// </summary>
        public virtual async Task SetOfflinePinAsync(
            string machineId,
            string encryptedPin,
            CancellationToken ct = default)
        {
            try
            {
                DateTimeOffset gmt7Time = DateTimeOffset.UtcNow.ToOffset(TimeSpan.FromHours(7));
                string timestamp = gmt7Time.ToString("o");

                await _client
                    .SetAsync($"machines/{machineId}/offline_pin", encryptedPin)
                    .ConfigureAwait(false);

                await _client
                    .SetAsync($"machines/{machineId}/last_updated", timestamp)
                    .ConfigureAwait(false);

                Logger.LogInfo($"[FireSharp] Offline PIN written for machines/{machineId}.");
            }
            catch (Exception ex)
            {
                Logger.LogFirebaseError(ex, "FirebaseService.SetOfflinePinAsync");
                throw;
            }
        }

        // ------------------------------------------------------------------ //
        //  Unlock Request (admin remote unlock command)                       //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Reads the current unlock request for this machine.
        /// Returns <c>null</c> when no command is pending.
        /// </summary>
        public virtual async Task<UnlockRequest> GetUnlockRequestAsync(
            string machineId,
            CancellationToken ct = default)
        {
            try
            {
                var response = await _client
                    .GetAsync($"machines/{machineId}/unlock_request")
                    .ConfigureAwait(false);

                if (response?.Body == null || response.Body == "null")
                    return null;

                UnlockRequest req = response.ResultAs<UnlockRequest>();

                // Validate minimum fields
                if (req == null || string.IsNullOrWhiteSpace(req.Token))
                    return null;

                return req;
            }
            catch (Exception ex)
            {
                Logger.LogFirebaseError(ex, "FirebaseService.GetUnlockRequestAsync");
                return null;
            }
        }

        /// <summary>
        /// Deletes the unlock request node — called atomically after a token
        /// has been picked up so it cannot be processed twice.
        /// </summary>
        public virtual async Task DeleteUnlockRequestAsync(
            string machineId,
            CancellationToken ct = default)
        {
            try
            {
                await _client
                    .DeleteAsync($"machines/{machineId}/unlock_request")
                    .ConfigureAwait(false);

                Logger.LogInfo($"[FireSharp] Unlock request consumed for machines/{machineId}.");
            }
            catch (Exception ex)
            {
                Logger.LogFirebaseError(ex, "FirebaseService.DeleteUnlockRequestAsync");
            }
        }

        // ------------------------------------------------------------------ //
        //  Heartbeat                                                          //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Updates the <c>last_seen</c> timestamp for this machine. Dashboard
        /// uses this field to determine whether the machine is online.
        /// </summary>
        public virtual async Task SetLastSeenAsync(
            string machineId,
            CancellationToken ct = default)
        {
            try
            {
                DateTimeOffset gmt7Time = DateTimeOffset.UtcNow.ToOffset(TimeSpan.FromHours(7));
                string timestamp = gmt7Time.ToString("o");

                await _client
                    .SetAsync($"machines/{machineId}/last_seen", timestamp)
                    .ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Logger.LogFirebaseError(ex, "FirebaseService.SetLastSeenAsync");
            }
        }

        // ------------------------------------------------------------------ //
        //  Re-lock interval                                                   //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Reads the <c>relock_after_seconds</c> value for this machine.
        /// Returns <c>null</c> when the field does not exist (never set),
        /// <c>0</c> when explicitly disabled, or the positive interval in seconds.
        /// </summary>
        public virtual async Task<int?> GetReLockIntervalAsync(
            string machineId,
            CancellationToken ct = default)
        {
            try
            {
                var response = await _client
                    .GetAsync($"machines/{machineId}/relock_after_seconds")
                    .ConfigureAwait(false);

                string body = response?.Body;

                if (string.IsNullOrWhiteSpace(body) || body == "null")
                    return null;

                try
                {
                    return response.ResultAs<int>();
                }
                catch
                {
                    string cleaned = body.Trim().Trim('"');
                    if (int.TryParse(cleaned, out int parsed))
                        return parsed;

                    Logger.LogWarning(
                        $"[FireSharp] Could not parse relock_after_seconds body: '{body}'");
                    return null;
                }
            }
            catch (Exception ex)
            {
                Logger.LogFirebaseError(ex, "FirebaseService.GetReLockIntervalAsync");
                return null;
            }
        }

        /// <summary>
        /// Quick connectivity check — returns <c>true</c> if Firebase is reachable.
        /// </summary>
        public virtual async Task<bool> IsAvailableAsync(CancellationToken ct = default)
        {
            try
            {
                var response = await _client
                    .GetAsync("machines/__ping__")
                    .ConfigureAwait(false);
                return response != null;
            }
            catch (Exception ex)
            {
                Logger.LogFirebaseError(ex, "FirebaseService.IsAvailableAsync");
                return false;
            }
        }

        // ------------------------------------------------------------------ //
        //  IDisposable                                                        //
        // ------------------------------------------------------------------ //

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            (_client as IDisposable)?.Dispose();
        }

        // ------------------------------------------------------------------ //
        //  Nested types                                                       //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Schema of <c>machines/{id}/unlock_request</c>.
        /// All fields are required to consider the request valid.
        /// </summary>
        public sealed class UnlockRequest
        {
            [JsonProperty("token")]
            public string Token { get; set; }

            [JsonProperty("issued_at")]
            public string IssuedAt { get; set; }

            [JsonProperty("expires_at")]
            public string ExpiresAt { get; set; }

            /// <summary>
            /// True when <see cref="ExpiresAt"/> is in the past.
            /// Returns <c>false</c> if the field is missing or unparseable
            /// (treated as expired to be safe).
            /// </summary>
            public bool IsExpired()
            {
                if (string.IsNullOrWhiteSpace(ExpiresAt)) return true;
                if (!DateTimeOffset.TryParse(ExpiresAt, out var expires)) return true;
                return DateTimeOffset.UtcNow > expires.ToUniversalTime();
            }
        }

        private sealed class FirebaseConfigFile
        {
            [JsonProperty("base_path")]
            public string BasePath { get; set; }

            [JsonProperty("auth_secret")]
            public string AuthSecret { get; set; }
        }
    }
}
