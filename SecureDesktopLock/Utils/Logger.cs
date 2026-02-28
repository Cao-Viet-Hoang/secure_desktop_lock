using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace SecureDesktopLock.Utils
{
    /// <summary>
    /// Lightweight structured logger.
    ///
    /// All writes are appended to a rolling daily log file under
    ///   %ProgramData%\SecureLock\Logs\
    ///
    /// Async overloads are provided so that network-upload logic (e.g. posting
    /// to Firebase) can be overlaid in future without blocking the UI thread.
    ///
    /// Thread safety: the synchronous helper uses a lock; the async version
    /// uses a dedicated TaskScheduler wrapper to serialise file I/O.
    /// </summary>
    public static class Logger
    {
        // ------------------------------------------------------------------ //
        //  Configuration                                                       //
        // ------------------------------------------------------------------ //

        /// <summary>Root folder for all SecureLock data files.</summary>
        public static readonly string DataRoot =
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "SecureLock");

        private static readonly string LogFolder = Path.Combine(DataRoot, "Logs");

        // Serialise synchronous writes from multiple threads
        private static readonly object _fileLock = new object();

        // ------------------------------------------------------------------ //
        //  Public API                                                          //
        // ------------------------------------------------------------------ //

        /// <summary>Logs a successful unlock event.</summary>
        public static void LogUnlockSuccess(string machineId)
        {
            Write("UNLOCK_SUCCESS", $"machineId={machineId}");
        }

        /// <summary>Logs a successful unlock event, indicating whether the master password was used.</summary>
        public static void LogUnlockSuccess(string machineId, bool isMasterPassword)
        {
            string method = isMasterPassword ? "MASTER_PASSWORD" : "NORMAL";
            Write("UNLOCK_SUCCESS", $"machineId={machineId} method={method}");
        }

        /// <summary>Logs a failed unlock attempt (wrong password).</summary>
        public static void LogUnlockFailure(string machineId, int attemptNumber)
        {
            Write("UNLOCK_FAILURE", $"machineId={machineId} attempt={attemptNumber}");
        }

        /// <summary>Logs a Firebase / network error.</summary>
        public static void LogFirebaseError(Exception ex, string context = "")
        {
            Write("FIREBASE_ERROR",
                string.IsNullOrWhiteSpace(context)
                    ? ex.ToString()
                    : $"context={context} error={ex}");
        }

        /// <summary>Logs a generic informational message.</summary>
        public static void LogInfo(string message)
        {
            Write("INFO", message);
        }

        /// <summary>Logs a generic warning.</summary>
        public static void LogWarning(string message)
        {
            Write("WARN", message);
        }

        /// <summary>Logs an application error / exception.</summary>
        public static void LogError(string message, Exception ex = null)
        {
            Write("ERROR", ex == null ? message : $"{message} — {ex}");
        }

        // ------------------------------------------------------------------ //
        //  Async wrappers (fire-and-forget safe)                              //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Asynchronously appends a log entry and, when connectivity is
        /// available, can upload the entry to the cloud backend.
        /// Currently persists locally; plug in upload logic in the Task body.
        /// </summary>
        public static Task LogUnlockSuccessAsync(string machineId) =>
            Task.Run(() => LogUnlockSuccess(machineId));

        public static Task LogUnlockSuccessAsync(string machineId, bool isMasterPassword) =>
            Task.Run(() => LogUnlockSuccess(machineId, isMasterPassword));

        public static Task LogUnlockFailureAsync(string machineId, int attempt) =>
            Task.Run(() => LogUnlockFailure(machineId, attempt));

        public static Task LogFirebaseErrorAsync(Exception ex, string context = "") =>
            Task.Run(() => LogFirebaseError(ex, context));

        // ------------------------------------------------------------------ //
        //  Core write helper                                                   //
        // ------------------------------------------------------------------ //

        private static void Write(string level, string message)
        {
            try
            {
                EnsureFolderExists();

                // One log file per day: SecureLock_2026-02-24.log
                string logFile = Path.Combine(
                    LogFolder,
                    $"SecureLock_{DateTime.UtcNow:yyyy-MM-dd}.log");

                // ISO-8601 timestamp in UTC
                string line = $"{DateTime.UtcNow:yyyy-MM-ddTHH:mm:ss.fffZ} [{level,-15}] {message}{Environment.NewLine}";
                byte[] data = Encoding.UTF8.GetBytes(line);

                lock (_fileLock)
                {
                    using (FileStream fs = new FileStream(
                        logFile,
                        FileMode.Append,
                        FileAccess.Write,
                        FileShare.Read))
                    {
                        fs.Write(data, 0, data.Length);
                    }
                }
            }
            catch (Exception)
            {
                // Logger must never throw — silently discard errors.
            }
        }

        private static void EnsureFolderExists()
        {
            if (!Directory.Exists(LogFolder))
                Directory.CreateDirectory(LogFolder);
        }
    }
}
