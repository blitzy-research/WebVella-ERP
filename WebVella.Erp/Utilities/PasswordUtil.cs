// Credentials are salted, work-factored PBKDF2-HMAC-SHA-256 in the ASP.NET Core versioned (V3) payload
// layout, verified in fixed time. Threat: C-03 (CWE-916, CWE-759 / OWASP A02:2021) - the unsalted MD5
// digest this replaces made a leaked password column recoverable wholesale from precomputed tables. Also
// closes M-06 (shared mutable MD5 instance) and M-05 (short-circuiting comparison).
// The MD5 path is RETAINED solely so credentials written by earlier releases keep working; do not delete
// it and do not add a global suppression for the CA5351 it causes, which is accepted in
// docs/security/risk-register.md along with the PBKDF2-versus-bcrypt/Argon2 deviation.
// PasswordHasher<T> is deliberately not used: since .NET 8 its verifier returns SuccessRehashNeeded for
// any value whose PRF is not HMAC-SHA-512, so it would re-persist every credential on every login.
using System;
using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace WebVella.Erp.Utilities
{
    public static class PasswordUtil
    {
        // The stored value is the self-describing ASP.NET Core V3 payload, Base64-encoded: a 0x01 marker, then
        // the PRF id, the iteration count and the salt length as big-endian uint32, then the salt and the derived
        // subkey. Recording the parameters alongside the value lets the work factor be raised later without
        // invalidating anything already written. Nothing here holds mutable state.
        private const byte FormatMarkerV3 = 0x01;

        /// <summary>HMAC-SHA-256, the framework's own KeyDerivationPrf value. The only PRF written.</summary>
        private const uint PrfHmacSha256 = 1;

        /// <summary>HMAC-SHA-512. Accepted on verification, never written - see <see cref="VerifyPbkdf2Hash"/>.</summary>
        private const uint PrfHmacSha512 = 2;

        /// <summary>
        /// The mandated work factor, and the out-of-date threshold: raising it migrates every
        /// credential on its owner's next authentication.
        /// </summary>
        private const int Pbkdf2IterationCount = 600_000;

        /// <summary>128 bits of salt, the mandated size, drawn from the OS CSPRNG.</summary>
        private const int Pbkdf2SaltByteLength = 16;

        /// <summary>256 bits of derived key material, matching the digest size of the chosen PRF.</summary>
        private const int Pbkdf2SubkeyByteLength = 32;

        /// <summary>Marker, PRF id, iteration count and salt length: 1 + 4 + 4 + 4 bytes.</summary>
        private const int PayloadHeaderByteLength = 13;

        // Acceptance bounds for parameters read back OUT of a stored value. These are hostile-input
        // guards: the values are attacker-controlled the moment anything can write to the password
        // column, and an unbounded iteration count or salt length read from a row would be CPU or
        // allocation exhaustion (CWE-400) on a path reachable without credentials. Checked before
        // any derivation is attempted.
        private const int MinAcceptedSaltByteLength = 8;
        private const int MaxAcceptedSaltByteLength = 128;
        private const int MinAcceptedSubkeyByteLength = 16;
        private const int MaxAcceptedSubkeyByteLength = 128;
        private const int MaxAcceptedIterationCount = 2_000_000;

        /// <summary>Decode bound. The column is varchar(500); a well-formed value is 84 characters.</summary>
        private const int MaxAcceptedEncodedLength = 512;
        /// <summary>
        /// The largest plaintext this utility will process; longer input is refused, never hashed.
        /// A resource bound (CWE-400, CWE-770), not a strength limit - the work factor that makes an
        /// offline guess costly also makes this an amplifier on the anonymous login path, so every
        /// entry point below tests it on string.Length FIRST, before any scan, encoding or derivation.
        /// </summary>
        internal const int MaxPasswordLength = 128;
        /// <summary>
        /// The shortest plaintext accepted for a NEW credential (M-13, CWE-521, mandated "12+").
        /// Field length metadata is advisory here and is not consulted on the write path, so this is
        /// the server-side half of that bound. Applied ONLY where a new plaintext becomes a stored
        /// hash, never when an already-verified credential is re-hashed during the format migration.
        /// </summary>
        internal const int MinPasswordLength = 12;

        /// <summary>The rendered length of a legacy MD5 digest: the legacy/modern discriminator.</summary>
        private const int Md5HexLength = 32;
        /// <summary>
        /// Tests a NEW plaintext credential against the length and character-class policy (M-13,
        /// CWE-521). Returns null when acceptable, otherwise a caller-safe reason that NEVER contains
        /// the plaintext, its length or any derivative - the reason is persisted to the system log,
        /// so embedding the value would be stored credential disclosure (CWE-532).
        /// </summary>
        internal static string ValidatePasswordPolicy(string password)
        {
            // Size before content, for the same reason every other entry point in this file orders
            // it that way: this runs on an authenticated write path, but an oversized value must
            // still cost one integer comparison rather than a full character scan.
            if (password != null && password.Length > MaxPasswordLength)
            {
                return "it is longer than the " + MaxPasswordLength.ToString(CultureInfo.InvariantCulture)
                    + " character maximum";
            }

            if (string.IsNullOrWhiteSpace(password))
            {
                return "it is empty";
            }

            if (password.Length < MinPasswordLength)
            {
                return "it is shorter than the " + MinPasswordLength.ToString(CultureInfo.InvariantCulture)
                    + " character minimum";
            }

            // Length alone is not the mandated policy: "aaaaaaaaaaaa" clears every test above. A
            // symbol is anything neither letter nor digit, so a space counts and a non-cased script
            // does not quietly satisfy mixed case.
            bool hasUpperCase = false;
            bool hasLowerCase = false;
            bool hasDigit = false;
            bool hasSymbol = false;

            foreach (char character in password)
            {
                if (char.IsUpper(character))
                {
                    hasUpperCase = true;
                }
                else if (char.IsLower(character))
                {
                    hasLowerCase = true;
                }
                else if (char.IsDigit(character))
                {
                    hasDigit = true;
                }
                else if (!char.IsLetterOrDigit(character))
                {
                    hasSymbol = true;
                }
            }

            if (hasUpperCase && hasLowerCase && hasDigit && hasSymbol)
            {
                return null;
            }

            // One message naming every missing class, so satisfying the policy is not an iterative
            // guessing game. The policy is not a secret.
            StringBuilder missingClasses = new StringBuilder();
            AppendMissingClass(missingClasses, !hasUpperCase, "an upper case letter");
            AppendMissingClass(missingClasses, !hasLowerCase, "a lower case letter");
            AppendMissingClass(missingClasses, !hasDigit, "a number");
            AppendMissingClass(missingClasses, !hasSymbol, "a symbol");

            return "it is missing " + missingClasses.ToString();
        }
        /// <summary>
        /// Hashes a password for storage. A fresh random salt per call means the same input never
        /// yields the same value, so the result must never be compared for equality and never inside
        /// a SQL predicate - use <see cref="VerifyPassword(string, string, out bool, out bool)"/>.
        /// Returns <see cref="string.Empty"/> for absent input, matching the contract the callers of
        /// <see cref="GetMd5Hash(string)"/> rely on, and throws
        /// <see cref="ArgumentOutOfRangeException"/> above <see cref="MaxPasswordLength"/>.
        /// </summary>
        internal static string HashPassword(string password)
        {
            if (password != null && password.Length > MaxPasswordLength)
            {
                throw new ArgumentOutOfRangeException(nameof(password),
                    "Password must be no longer than " + MaxPasswordLength + " characters.");
            }

            if (string.IsNullOrWhiteSpace(password))
            {
                return string.Empty;
            }

            // A fresh salt per credential makes two identical passwords hash differently and a
            // precomputed table useless. RandomNumberGenerator is the OS CSPRNG, as mandated.
            byte[] salt = RandomNumberGenerator.GetBytes(Pbkdf2SaltByteLength);

            byte[] subkey = Rfc2898DeriveBytes.Pbkdf2(
                password,
                salt,
                Pbkdf2IterationCount,
                HashAlgorithmName.SHA256,
                Pbkdf2SubkeyByteLength);

            byte[] payload = new byte[PayloadHeaderByteLength + salt.Length + subkey.Length];
            payload[0] = FormatMarkerV3;
            BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), PrfHmacSha256);
            BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(5, 4), Pbkdf2IterationCount);
            BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(9, 4), (uint)salt.Length);
            Buffer.BlockCopy(salt, 0, payload, PayloadHeaderByteLength, salt.Length);
            Buffer.BlockCopy(subkey, 0, payload, PayloadHeaderByteLength + salt.Length, subkey.Length);

            return Convert.ToBase64String(payload);
        }
        /// <summary>
        /// Hashes a password for storage. A fresh random salt per call means the same input never yields the
        /// same value, so the result must never be compared for equality and never inside a SQL predicate - use
        /// <see cref="VerifyPassword(string, string, out bool, out bool)"/>. Returns
        /// <see cref="string.Empty"/> for absent input, matching the contract callers of
        /// <see cref="GetMd5Hash(string)"/> rely on, and THROWS
        /// <see cref="ArgumentOutOfRangeException"/> above <see cref="MaxPasswordLength"/> rather than
        /// returning empty, because an empty stored value can never verify and would lock the account out
        /// irreversibly. Safe at all three call sites: the rehash path cannot reach the bound, the two
        /// record-write collectors run inside handlers that turn an exception into an unsuccessful
        /// QueryResponse, and SecurityManager.SaveUser validates first.
        /// </summary>
        internal static bool VerifyPassword(string password, string storedHash, out bool needsRehash,
            out bool keyDerivationPerformed)
        {
            needsRehash = false;
            keyDerivationPerformed = false;

            // This is the entry point the anonymous login endpoint reaches, so size precedes content.
            // Refusal is a plain false, indistinguishable from any other failed attempt.
            if (password != null && password.Length > MaxPasswordLength)
            {
                return false;
            }

            // Fail closed on absent input, and never raise on the login path.
            if (string.IsNullOrWhiteSpace(password) || string.IsNullOrWhiteSpace(storedHash))
            {
                return false;
            }

            // Route on the stored shape rather than trying the modern verifier first: that keeps
            // existing credentials working without a forced reset.
            if (IsLegacyHash(storedHash))
            {
                if (!VerifyMd5Hash(password, storedHash))
                {
                    return false;
                }

                needsRehash = true;
                return true;
            }

            return VerifyPbkdf2Hash(password, storedHash, out needsRehash, out keyDerivationPerformed);
        }
        /// <summary>
        /// Verifies a password against a stored value in EITHER format - modern PBKDF2 or a legacy MD5 digest.
        /// The enabling member for the credential migration, because a salted hash cannot be compared by SQL
        /// equality. Never throws for a corrupt stored value: one damaged row must not become a denial of
        /// service on the login path.
        /// </summary>
        /// <param name="needsRehash">
        /// True only on SUCCESS against an out-of-date value - a legacy digest, or an iteration count below
        /// <see cref="Pbkdf2IterationCount"/>. Always false on failure, so a failed attempt cannot trigger a
        /// write.
        /// </param>
        /// <param name="keyDerivationPerformed">
        /// True if and only if a PBKDF2 derivation actually ran, so a caller that found no account can spend a
        /// compensating one (CWE-208, CWE-203). The caller cannot predict this, because an over-long password
        /// and a corrupt payload both return on cheap guards, and each mispredicted case is an oracle.
        /// </param>
        private static bool VerifyPbkdf2Hash(string password, string storedHash, out bool needsRehash,
            out bool keyDerivationPerformed)
        {
            needsRehash = false;

            // Stays false through every guard below: each is a cheap rejection, so a request leaving
            // through one still owes its caller a compensating derivation.
            keyDerivationPerformed = false;

            if (storedHash.Length > MaxAcceptedEncodedLength)
            {
                return false;
            }

            // Sized to the maximum a Base64 string of this length can decode to; a length that is not
            // a multiple of four is reported by the non-throwing decode rather than by an exception.
            byte[] payload = new byte[(storedHash.Length / 4) * 3];
            if (!Convert.TryFromBase64String(storedHash, payload, out int payloadLength))
            {
                return false;
            }

            if (payloadLength <= PayloadHeaderByteLength || payload[0] != FormatMarkerV3)
            {
                return false;
            }

            uint prf = BinaryPrimitives.ReadUInt32BigEndian(new ReadOnlySpan<byte>(payload, 1, 4));
            uint iterations = BinaryPrimitives.ReadUInt32BigEndian(new ReadOnlySpan<byte>(payload, 5, 4));
            uint saltLength = BinaryPrimitives.ReadUInt32BigEndian(new ReadOnlySpan<byte>(payload, 9, 4));

            HashAlgorithmName algorithm;
            if (prf == PrfHmacSha256)
            {
                algorithm = HashAlgorithmName.SHA256;
            }
            else if (prf == PrfHmacSha512)
            {
                algorithm = HashAlgorithmName.SHA512;
            }
            else
            {
                return false;
            }

            if (iterations < 1 || iterations > MaxAcceptedIterationCount)
            {
                return false;
            }

            if (saltLength < MinAcceptedSaltByteLength || saltLength > MaxAcceptedSaltByteLength)
            {
                return false;
            }

            // A long on purpose: saltLength is a uint read from the payload, so the subtraction must
            // not wrap into a plausible-looking positive length.
            long subkeyLength = payloadLength - PayloadHeaderByteLength - (long)saltLength;
            if (subkeyLength < MinAcceptedSubkeyByteLength || subkeyLength > MaxAcceptedSubkeyByteLength)
            {
                return false;
            }

            byte[] salt = new byte[saltLength];
            Buffer.BlockCopy(payload, PayloadHeaderByteLength, salt, 0, (int)saltLength);

            byte[] expectedSubkey = new byte[subkeyLength];
            Buffer.BlockCopy(payload, PayloadHeaderByteLength + (int)saltLength, expectedSubkey, 0, (int)subkeyLength);

            // Set BEFORE the derivation, so the flag is already true if the derivation itself throws.
            keyDerivationPerformed = true;

            byte[] actualSubkey = Rfc2898DeriveBytes.Pbkdf2(
                password,
                salt,
                (int)iterations,
                algorithm,
                (int)subkeyLength);

            // Fixed-time comparison (M-05, CWE-208), as mandated. Both spans are equal length by
            // construction, which is the condition under which FixedTimeEquals is fixed-time.
            if (!CryptographicOperations.FixedTimeEquals(expectedSubkey, actualSubkey))
            {
                return false;
            }

            needsRehash = iterations < Pbkdf2IterationCount;
            return true;
        }

        /// <summary>
        /// A throwaway per-process salt for <see cref="PerformDummyVerification(string)"/>, generated
        /// rather than written as a literal so no constant here can be mistaken for key material.
        /// </summary>
        private static readonly byte[] dummyVerificationSalt = RandomNumberGenerator.GetBytes(Pbkdf2SaltByteLength);

        /// <summary>
        /// Verifies against a modern PBKDF2 value using the parameters recorded inside it, and reports whether
        /// those parameters are weaker than the current target.
        /// </summary>
        /// <remarks>
        /// Does not throw for MALFORMED STORED INPUT: every payload field is range-checked before use and the
        /// Base64 decode is non-throwing, so a corrupt row returns false rather than a 500 on an endpoint
        /// reachable without credentials. The guards run cheapest-first and all precede any derivation, because
        /// the iteration count and salt length come out of the stored value and are attacker-controlled.
        /// HMAC-SHA-512 is accepted although never written, for values from an interim build, and is NOT flagged
        /// for re-hashing: at the same iteration count it costs more per guess, so converting one would reduce
        /// the work factor. Every other PRF is rejected outright.
        /// </remarks>
        internal static void PerformDummyVerification(string password)
        {
            // The SAME bound in the SAME position as VerifyPassword's first action, and not thrift: without it an
            // over-length submission answered instantly for an EXISTING address and paid a full derivation for a
            // NON-EXISTENT one, so slow meant "no such account" - this member's own oracle, inverted.
            if (password != null && password.Length > MaxPasswordLength)
            {
                return;
            }

            byte[] discarded = Rfc2898DeriveBytes.Pbkdf2(
                password ?? string.Empty,
                dummyVerificationSalt,
                Pbkdf2IterationCount,
                HashAlgorithmName.SHA256,
                Pbkdf2SubkeyByteLength);

            // Zeroing is hygiene, and an observable use of the result, so no compiler or runtime may
            // elide the derivation above as dead code.
            CryptographicOperations.ZeroMemory(discarded);
        }


        /// <summary>Appends one missing-character-class phrase to a policy message, comma separated.</summary>
        private static void AppendMissingClass(StringBuilder target, bool isMissing, string description)
        {
            if (!isMissing)
            {
                return;
            }

            if (target.Length > 0)
            {
                target.Append(", ");
            }

            target.Append(description);
        }
        /// <summary>
        /// Spends the work a real modern verification would spend and discards it. Call this on a
        /// credential-resolution path about to fail WITHOUT having performed a modern verification, so the
        /// failure costs the same as a success; the password is derivation input only.
        /// Moving verification out of the SQL predicate, which a per-credential salt makes unavoidable, would
        /// otherwise create an account-enumeration oracle (CWE-208, CWE-203): an unknown address answers in
        /// under a millisecond while a known one pays the full derivation. LoginThrottleService bounds the
        /// amplification this exposes.
        /// </summary>
        internal static bool IsLegacyHash(string storedHash)
        {
            if (storedHash == null || storedHash.Length != Md5HexLength)
            {
                return false;
            }

            for (int i = 0; i < storedHash.Length; i++)
            {
                if (!char.IsAsciiHexDigit(storedHash[i]))
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Reports whether a stored value is a legacy MD5 digest rather than a modern PBKDF2 value. The shapes
        /// are unambiguous - exactly <see cref="Md5HexLength"/> hexadecimal characters versus an 84-character
        /// Base64 string - so no new column is needed to tell them apart. Either casing is accepted, because the
        /// comparison this replaces was case-insensitive and rejecting an upper-case value would lock that
        /// account out. Internal rather than private because the version 4 data migration needs this test.
        /// </summary>
        internal static string GetMd5Hash(string input)
        {
            // MD5 is fast but not free, and this is reachable from the anonymous login path through
            // VerifyMd5Hash, so it carries the same bound as the modern primitive.
            if (input != null && input.Length > MaxPasswordLength)
            {
                return string.Empty;
            }

			if (string.IsNullOrWhiteSpace(input))
				return string.Empty;

            // M-06 (CWE-362) - the shared static MD5 instance this replaces was not thread-safe, so
            // two simultaneous authentications could interleave inside ComputeHash.
            byte[] data = MD5.HashData(Encoding.UTF8.GetBytes(input));

            StringBuilder sBuilder = new StringBuilder();
            for (int i = 0; i < data.Length; i++)
                sBuilder.Append(data[i].ToString("x2"));

            return sBuilder.ToString();
        }

        /// <summary>
        /// Renders the MD5 digest of the supplied text as lower-case hexadecimal. LEGACY SUPPORT ONLY: it must
        /// NEVER produce a newly persisted value. MD5 being unsalted and fast is what made C-03 Critical and why
        /// CA5351 reports here, accepted in docs/security/risk-register.md. Returns
        /// <see cref="string.Empty"/> for absent input, preserved because callers depend on it.
        /// </summary>
        internal static bool VerifyMd5Hash(string input, string hash)
        {
            // Both operands are bounded before use. The digest bound is exact rather than generous,
            // because a legacy digest is by definition Md5HexLength characters, so any other length
            // cannot match and is refused before ToLowerInvariant and UTF-8 encoding allocate.
            if ((input != null && input.Length > MaxPasswordLength)
                || (hash != null && hash.Length != Md5HexLength))
            {
                return false;
            }

            // Fail closed on absent input: the comparison this replaces returned TRUE for an empty
            // password against an empty stored digest, because both collapsed to string.Empty.
            if (string.IsNullOrWhiteSpace(input) || string.IsNullOrWhiteSpace(hash))
            {
                return false;
            }

            string hashOfInput = GetMd5Hash(input);

            // M-05 (CWE-208) - the StringComparer comparison this replaces short-circuited at the first differing
            // character, so its duration revealed how many leading characters were correct. Casing is normalised
            // first to keep the previous tolerance, which is not secret-dependent branching.
            byte[] expected = Encoding.UTF8.GetBytes(hashOfInput);
            byte[] actual = Encoding.UTF8.GetBytes(hash.ToLowerInvariant());

            if (expected.Length != actual.Length)
            {
                return false;
            }

            return CryptographicOperations.FixedTimeEquals(expected, actual);
        }

    }
}
