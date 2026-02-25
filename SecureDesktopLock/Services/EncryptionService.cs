using System;

namespace SecureDesktopLock.Services
{
    /// <summary>
    /// No-op passthrough "encryption" service.
    ///
    /// Encryption is currently disabled — passwords are stored and retrieved
    /// as plain text. Replace the bodies of <see cref="Encrypt"/> and
    /// <see cref="Decrypt"/> with real crypto (e.g. DPAPI) when needed.
    /// </summary>
    public sealed class EncryptionService
    {
        // ------------------------------------------------------------------
        //  Public API
        // ------------------------------------------------------------------

        /// <summary>
        /// Returns <paramref name="plainText"/> unchanged.
        /// </summary>
        public string Encrypt(string plainText)
        {
            if (plainText == null) throw new ArgumentNullException(nameof(plainText));
            return plainText;
        }

        /// <summary>
        /// Returns <paramref name="storedValue"/> unchanged.
        /// Returns <c>null</c> if the input is null/empty.
        /// </summary>
        public string Decrypt(string storedValue)
        {
            if (string.IsNullOrEmpty(storedValue)) return null;
            return storedValue;
        }

        /// <summary>
        /// Always succeeds for non-null/non-empty input.
        /// Returns <c>true</c> and sets <paramref name="plainText"/> to the stored value.
        /// </summary>
        public bool TryDecrypt(string storedValue, out string plainText)
        {
            plainText = Decrypt(storedValue);
            return plainText != null;
        }
    }
}
