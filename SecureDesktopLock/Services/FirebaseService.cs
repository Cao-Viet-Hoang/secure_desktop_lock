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
    ///   machines/{machineId}/current_password  : string
    ///   machines/{machineId}/backup_password   : string
    ///   machines/{machineId}/last_updated       : string  (ISO-8601 GMT+7)
    ///
    /// Configuration
    /// -------------
    /// The service reads its settings from a JSON file whose path is stored in
    /// App.config under the key "FirebaseConfigPath".  See
    /// firebase_config.example.json in the repo root for the required format:
    ///
    ///   {
    ///     "base_path":   "https://&lt;project-id&gt;-default-rtdb.firebaseio.com/",
    ///     "auth_secret": "&lt;your-database-secret&gt;"
    ///   }
    ///
    /// The Database Secret can be found in:
    ///   Firebase Console → Project Settings → Service Accounts → Database Secrets
    /// </summary>
    public class FirebaseService : IDisposable
    {
        // ------------------------------------------------------------------ //
        //  Fields                                                             //
        // ------------------------------------------------------------------ //
        private readonly IFirebaseClient _client;
        private bool _disposed;

        // ------------------------------------------------------------------ //
        //  Constructor                                                        //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Creates the service from an <see cref="IFirebaseClient"/> instance.
        /// Use the static factory <see cref="CreateFromConfigFile"/> to build
        /// from the JSON file specified in App.config.
        /// </summary>
        public FirebaseService(IFirebaseClient client)
        {
            _client = client ?? throw new ArgumentNullException(nameof(client));
        }

        /// <summary>
        /// Internal constructor used only by subclasses (e.g. null-object stubs).
        /// </summary>
        protected FirebaseService() { }

        /// <summary>
        /// Loads the Firebase configuration from the path stored in App.config
        /// key "FirebaseConfigPath", then creates and returns a
        /// <see cref="FirebaseService"/> instance backed by FireSharp.
        /// </summary>
        public static FirebaseService CreateFromConfigFile()
        {
            string path = System.Configuration.ConfigurationManager
                .AppSettings["FirebaseConfigPath"];

            if (string.IsNullOrWhiteSpace(path))
                throw new InvalidOperationException(
                    "App.config key 'FirebaseConfigPath' is not set.");

            // Resolve relative paths against the directory of the running executable.
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
        //  Public API                                                         //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Fetches the password string for this machine from the Realtime Database.
        /// Returns <c>null</c> when the node does not exist yet.
        /// </summary>
        public virtual async Task<string> GetPasswordAsync(
            string machineId,
            CancellationToken ct = default)
        {
            try
            {
                var response = await _client
                    .GetAsync($"machines/{machineId}/current_password")
                    .ConfigureAwait(false);

                if (response?.Body == null || response.Body == "null")
                {
                    Logger.LogInfo($"[FireSharp] Node machines/{machineId}/current_password does not exist.");
                    return null;
                }

                // ResultAs<string>() handles both quoted JSON strings and plain values
                return response.ResultAs<string>();
            }
            catch (Exception ex)
            {
                Logger.LogFirebaseError(ex, "FirebaseService.GetPasswordAsync");
                throw;
            }
        }

        /// <summary>
        /// Writes (creates or overwrites) the current password for this machine
        /// in the Realtime Database.
        /// </summary>
        public virtual async Task SetPasswordAsync(
            string machineId,
            string encryptedPassword,
            CancellationToken ct = default)
        {
            try
            {
                // Convert UTC time to GMT+7 (UTC+7)
                DateTimeOffset gmt7Time = DateTimeOffset.UtcNow.ToOffset(TimeSpan.FromHours(7));
                string timestamp = gmt7Time.ToString("o");

                // Write each child individually so that sibling keys
                // (e.g. relock_after_seconds) are never overwritten.
                // FireSharp's UpdateAsync/SetAsync on the parent node can
                // replace the entire node depending on the library version.
                await _client
                    .SetAsync($"machines/{machineId}/current_password", encryptedPassword)
                    .ConfigureAwait(false);

                await _client
                    .SetAsync($"machines/{machineId}/last_updated", timestamp)
                    .ConfigureAwait(false);

                Logger.LogInfo($"[FireSharp] Current password written for machines/{machineId}.");
            }
            catch (Exception ex)
            {
                Logger.LogFirebaseError(ex, "FirebaseService.SetPasswordAsync");
                throw;
            }
        }

        /// <summary>
        /// Fetches the backup password string for this machine from the Realtime Database.
        /// Returns <c>null</c> when the node does not exist yet.
        /// </summary>
        public virtual async Task<string> GetBackupPasswordAsync(
            string machineId,
            CancellationToken ct = default)
        {
            try
            {
                var response = await _client
                    .GetAsync($"machines/{machineId}/backup_password")
                    .ConfigureAwait(false);

                if (response?.Body == null || response.Body == "null")
                {
                    Logger.LogInfo($"[FireSharp] Node machines/{machineId}/backup_password does not exist.");
                    return null;
                }

                return response.ResultAs<string>();
            }
            catch (Exception ex)
            {
                Logger.LogFirebaseError(ex, "FirebaseService.GetBackupPasswordAsync");
                throw;
            }
        }

        /// <summary>
        /// Writes (creates or overwrites) the backup password for this machine
        /// in the Realtime Database.
        /// </summary>
        public virtual async Task SetBackupPasswordAsync(
            string machineId,
            string encryptedPassword,
            CancellationToken ct = default)
        {
            try
            {
                DateTimeOffset gmt7Time = DateTimeOffset.UtcNow.ToOffset(TimeSpan.FromHours(7));
                string timestamp = gmt7Time.ToString("o");

                await _client
                    .SetAsync($"machines/{machineId}/backup_password", encryptedPassword)
                    .ConfigureAwait(false);

                await _client
                    .SetAsync($"machines/{machineId}/last_updated", timestamp)
                    .ConfigureAwait(false);

                Logger.LogInfo($"[FireSharp] Backup password written for machines/{machineId}.");
            }
            catch (Exception ex)
            {
                Logger.LogFirebaseError(ex, "FirebaseService.SetBackupPasswordAsync");
                throw;
            }
        }

        /// <summary>
        /// Reads the <c>relock_after_seconds</c> value for this machine.
        /// Returns <c>null</c> when the field does not exist (never set),
        /// <c>0</c> when explicitly set to 0 (disabled), or the positive
        /// interval in seconds.
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

                // Field does not exist in Firebase
                if (string.IsNullOrWhiteSpace(body) || body == "null")
                    return null;

                // Firebase may return the value as a bare number (300) or
                // as a quoted string ("300").  Handle both cases.
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
        /// Quick connectivity check — returns <c>true</c> if Firebase is
        /// reachable.
        /// </summary>
        public virtual async Task<bool> IsAvailableAsync(CancellationToken ct = default)
        {
            try
            {
                var response = await _client
                    .GetAsync("machines/__ping__")
                    .ConfigureAwait(false);
                // Any HTTP response (including 404/null body) means we reached Firebase.
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
        //  Private helpers                                                    //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Represents the JSON shape stored at <c>machines/{machineId}</c>.
        /// </summary>
        private sealed class MachinePasswordEntry
        {
            [JsonProperty("current_password")]
            public string CurrentPassword { get; set; }

            [JsonProperty("last_updated")]
            public string LastUpdated { get; set; }
        }

        /// <summary>
        /// Typed deserialization target for the firebase_config.json file.
        /// </summary>
        private sealed class FirebaseConfigFile
        {
            [JsonProperty("base_path")]
            public string BasePath { get; set; }

            [JsonProperty("auth_secret")]
            public string AuthSecret { get; set; }
        }
    }
}
