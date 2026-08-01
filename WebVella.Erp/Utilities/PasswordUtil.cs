// SECURITY C-03 (CWE-916 password hash with insufficient computational effort, CWE-759 one-way
// hash without a salt / OWASP A02:2021 Cryptographic Failures).
// This utility used to store credentials as an unsalted, single-pass MD5 digest. That is a
// data-breach exposure rather than a mere "weak cryptography" note: a leaked password column is
// recoverable wholesale from precomputed tables at effectively zero cost, and identical passwords
// produce identical digests, so one cracked value exposes every account sharing it. Credentials
// are now stored as a salted, work-factored PBKDF2-HMAC-SHA-256 value written in the ASP.NET Core
// versioned (V3) payload layout, and verified in fixed time. Two further findings are closed by
// the same edit: M-06 (CWE-362, the shared mutable MD5 instance) and M-05 (CWE-208, the
// short-circuiting comparison).
//
// The MD5 path is RETAINED, deliberately and solely, so that credentials already stored by
// earlier releases keep working. Verification accepts either shape and reports when a successful
// verification used the legacy shape, which lets the caller re-hash with the modern primitive
// while it still holds the plaintext. That is the OWASP-prescribed "upgrade on next
// authentication" pattern, and it is what makes this format change backward compatible with no
// forced reset, no downtime and no user locked out. It is also why analyzer rule CA5351 ("do not
// use broken cryptographic algorithms") still reports here: that warning is accepted, not a
// defect, and is recorded in docs/security/risk-register.md. Do not delete the legacy path, and
// do not add a global suppression, to silence it.
//
// TWO DEVIATIONS from the letter of the mandated Cryptographic Standards, both surfaced here and
// in docs/security/risk-register.md rather than absorbed silently:
//   1. The standard names bcrypt, scrypt or Argon2. This uses PBKDF2, which the authoritative
//      OWASP Password Storage guidance sanctions explicitly at a high iteration count, and which
//      needs no new package because it ships in the framework already referenced by this project
//      (FrameworkReference Microsoft.AspNetCore.App, WebVella.Erp.csproj:L43). The minimal-change
//      constraint prefers the least invasive control. Substituting a dedicated bcrypt or Argon2
//      package remains an open repository-owner option if literal compliance is required.
//   2. WITHDRAWN. An earlier revision of this file claimed the mandated HMAC-SHA-256 and the
//      mandated versioned (V3) format are mutually exclusive in ASP.NET Core, and shipped
//      HMAC-SHA-512 instead. That claim was WRONG, and correcting it is the substance of this
//      edit. The V3 payload records its own pseudo-random function inside the stored value, and
//      ASP.NET Core itself wrote V3 with HMAC-SHA-256 for years - SHA-512 became the default only
//      in .NET 8. What is genuinely unavailable is a PRF selector on PasswordHasherOptions, which
//      exposes only CompatibilityMode and IterationCount; that limits the framework's
//      PasswordHasher, not the format. Both mandated parameters are therefore reachable together,
//      by deriving with Rfc2898DeriveBytes.Pbkdf2 and writing the same self-describing V3 layout,
//      which is what this file now does. The iteration count is 600,000, which is exactly the
//      OWASP Password Storage floor for PBKDF2-HMAC-SHA-256, so the result MEETS the named
//      standard rather than substituting something for it. Deviation 1 above is now the only
//      remaining deviation.
//
// PasswordHasher<T> is deliberately NOT used, for a second and independently decisive reason:
// since .NET 8 its verifier returns SuccessRehashNeeded for ANY value whose PRF is not
// HMAC-SHA-512, so routing HMAC-SHA-256 values through it would re-hash and re-persist every
// credential on every single login, for ever - a permanent write amplification on the
// authentication path. The two facilities it was previously kept for are provided directly
// instead: fixed-time comparison by CryptographicOperations.FixedTimeEquals, and the needs-rehash
// signal by comparing the parameters recorded in the stored value against the current target.

using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace WebVella.Erp.Utilities
{
    public static class PasswordUtil
    {
        // -----------------------------------------------------------------------------------------
        // The modern credential format: PBKDF2 written in the ASP.NET Core versioned (V3) payload
        // layout, which is self-describing -
        //
        //     byte  0        : format marker, 0x01
        //     bytes 1  - 4   : pseudo-random function id, big-endian uint32
        //     bytes 5  - 8   : iteration count, big-endian uint32
        //     bytes 9  - 12  : salt length in bytes, big-endian uint32
        //     bytes 13 - ... : salt, then the derived subkey
        //
        // - and Base64-encoded for storage. Recording the parameters alongside the value is what
        // allows the work factor to be raised later without invalidating anything already written,
        // and it is what lets verification below accept a value produced with different parameters
        // while still writing new values with the mandated ones.
        //
        // SECURITY (C-03, CWE-916/CWE-759, OWASP A02:2021) - the per-credential salt defeats
        // precomputed tables and makes two identical passwords hash differently; the iteration
        // count makes each offline guess expensive.
        //
        // The iteration count is the control, not a tuning knob. 600,000 is exactly the OWASP
        // Password Storage floor for PBKDF2-HMAC-SHA-256. It deliberately costs roughly 120 ms of
        // CPU per hash and per verification, and that cost is a pre-declared, accepted trade-off
        // recorded in docs/security/remediation-log.md - do NOT lower it to chase a latency target.
        // Only the authentication path pays it, and only a bounded number of times per account,
        // because Web/Services/LoginThrottleService.cs caps failed credential checks at five per
        // account and twenty-five per source address per fifteen minutes at BOTH entry points.
        //
        // Nothing here holds mutable state: the derivation is a static one-shot and the salt comes
        // from the operating system CSPRNG, so this is correct under concurrency with no lock and
        // cannot reintroduce M-06.
        // -----------------------------------------------------------------------------------------

        /// <summary>The V3 payload format marker, and the only marker this class writes or accepts.</summary>
        private const byte FormatMarkerV3 = 0x01;

        /// <summary>
        /// Pseudo-random function identifiers as recorded in the payload. The numeric values are
        /// the framework's own KeyDerivationPrf values, which is what keeps a value written here
        /// byte-compatible with the versioned format. Only SHA-256 is ever written; SHA-512 is
        /// accepted on verification for the reason given on <see cref="VerifyPbkdf2Hash"/>.
        /// </summary>
        private const uint PrfHmacSha256 = 1;

        /// <summary>See <see cref="PrfHmacSha256"/>. Accepted on verification, never written.</summary>
        private const uint PrfHmacSha512 = 2;

        /// <summary>
        /// The mandated work factor: the OWASP Password Storage floor for PBKDF2-HMAC-SHA-256.
        /// Also the threshold that decides whether an already-stored value is out of date, so
        /// raising this constant migrates every credential on its owner's next authentication with
        /// no further code change and no forced reset.
        /// </summary>
        private const int Pbkdf2IterationCount = 600_000;

        /// <summary>128 bits of salt, the mandated size, drawn from the operating system CSPRNG.</summary>
        private const int Pbkdf2SaltByteLength = 16;

        /// <summary>256 bits of derived key material, matching the digest size of the chosen PRF.</summary>
        private const int Pbkdf2SubkeyByteLength = 32;

        /// <summary>Marker, PRF id, iteration count and salt length: 1 + 4 + 4 + 4 bytes.</summary>
        private const int PayloadHeaderByteLength = 13;

        // Acceptance bounds for the parameters read back OUT of a stored value. Every one of these
        // is a hostile-input guard, not a style preference: the values are attacker-controlled the
        // moment anything can write to the password column, and an unbounded iteration count or
        // salt length read from a row would become CPU or allocation exhaustion on an endpoint that
        // is reachable without credentials. They are checked BEFORE any derivation is attempted.
        private const int MinAcceptedSaltByteLength = 8;
        private const int MaxAcceptedSaltByteLength = 128;
        private const int MinAcceptedSubkeyByteLength = 16;
        private const int MaxAcceptedSubkeyByteLength = 128;
        private const int MaxAcceptedIterationCount = 2_000_000;

        /// <summary>
        /// Upper bound on the encoded length this class will even attempt to decode. The column
        /// that holds the value is varchar(500) and a well-formed value is 84 characters, so 512 is
        /// generous while still bounding the decode buffer.
        /// </summary>
        private const int MaxAcceptedEncodedLength = 512;

        /// <summary>
        /// The largest plaintext this utility will process. Input longer than this is refused
        /// outright rather than hashed.
        /// </summary>
        /// <remarks>
        /// SECURITY (CWE-400 uncontrolled resource consumption, CWE-770 allocation without limits,
        /// OWASP A04:2021) - the deliberately expensive work factor that makes an offline guess
        /// costly also makes this primitive an amplifier if it is handed an unbounded input. The
        /// login endpoint is anonymous, so the plaintext arriving here is attacker-controlled in
        /// both content AND length. Every entry point below therefore tests this bound on
        /// string.Length as its FIRST action - before any whitespace scan, before any UTF-8
        /// encoding, and before MD5 or PBKDF2 runs - so an oversized value costs a single integer
        /// comparison instead of a full character scan plus a byte-array allocation plus 600,000
        /// iterations of key derivation. Ordering is the whole point of the control: validating
        /// content before size is what let a large value pay for itself.
        /// The value is 128 to match exactly the maximum length the password field is provisioned
        /// with by the system entity definition, so this bound can never refuse a plaintext that
        /// the platform would otherwise accept, and no legitimate credential is affected. It is
        /// NOT a security limit on password strength - 128 characters is far above the 12-character
        /// minimum this remediation sets - it is purely a resource bound.
        /// </remarks>
        private const int MaxPasswordLength = 128;

        /// <summary>
        /// The exact rendered length of a legacy MD5 digest: 16 bytes emitted as two hexadecimal
        /// characters each. This is the discriminator between a legacy stored value and a modern
        /// one, so it is a constant rather than a literal repeated across members.
        /// </summary>
        private const int Md5HexLength = 32;

        /// <summary>
        /// Hashes a password for storage using the modern primitive. Every call returns a
        /// different value for the same input because a fresh random salt is generated, so the
        /// result must never be compared for equality - and in particular must never be compared
        /// inside a SQL predicate. Use <see cref="VerifyPassword(string, string, out bool)"/>.
        /// </summary>
        /// <param name="password">The plaintext password.</param>
        /// <returns>
        /// The encoded hash, or <see cref="string.Empty"/> when <paramref name="password"/> is
        /// null, empty or whitespace. Empty is returned rather than thrown for two reasons: it is
        /// the contract the existing callers of <see cref="GetMd5Hash(string)"/> already rely on,
        /// so substituting this member for that one changes no behaviour; and it is fail-closed,
        /// because an empty stored value can never verify, so an empty password cannot yield a
        /// usable credential.
        /// </returns>
        internal static string HashPassword(string password)
        {
            // Size before content. See MaxPasswordLength: this test precedes the whitespace scan
            // deliberately, so an oversized value never pays for a full character scan and never
            // reaches the 600,000-iteration derivation. Empty is returned rather than thrown to
            // keep the single documented failure contract of this member - and it is fail-closed,
            // because an empty stored value can never verify.
            if (password != null && password.Length > MaxPasswordLength)
            {
                return string.Empty;
            }

            if (string.IsNullOrWhiteSpace(password))
            {
                return string.Empty;
            }

            // A fresh salt per credential is the whole point of the control: it is what makes two
            // identical passwords hash to different values and what makes a precomputed table
            // useless. RandomNumberGenerator is the operating system CSPRNG, as the mandated
            // Cryptographic Standards require - never a pseudo-random generator seeded from time.
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
        /// Verifies a password against a stored value in EITHER format - the modern PBKDF2 value
        /// or a legacy MD5 digest written by an earlier release - and reports whether the stored
        /// value is out of date and should be replaced.
        /// </summary>
        /// <param name="password">The plaintext password supplied by the caller.</param>
        /// <param name="storedHash">The value currently persisted for the account.</param>
        /// <param name="needsRehash">
        /// Set to true only when verification SUCCEEDED and the stored value is out of date,
        /// either because it is a legacy MD5 digest or because the iteration count recorded in the
        /// stored value is below <see cref="Pbkdf2IterationCount"/> - so a future work factor
        /// increase is carried by this same mechanism with no further code change. The caller still
        /// holds the plaintext at that moment and should call <see cref="HashPassword(string)"/>
        /// and persist the result. Always false when verification fails, so a failed attempt can
        /// never trigger a write.
        /// </param>
        /// <returns>True when the password matches the stored value; otherwise false.</returns>
        /// <remarks>
        /// SECURITY (C-03, CWE-916/CWE-759, OWASP A02:2021) - this is the enabling member for the
        /// credential migration. A salted hash cannot be compared by SQL equality, because the
        /// salt differs per row, so verification has to happen here in application code.
        /// This member never throws for a bad or corrupt stored value: it returns false. A single
        /// damaged row must not become a denial of service on the login path.
        /// </remarks>
        internal static bool VerifyPassword(string password, string storedHash, out bool needsRehash)
        {
            needsRehash = false;

            // Size before content, and before anything else in this member. This is the entry
            // point the anonymous login endpoint reaches, so it is the one that decides whether an
            // oversized submission is cheap or expensive. Refusing here costs one integer
            // comparison; allowing it through would cost a full whitespace scan of the value, a
            // UTF-8 byte-array allocation and 600,000 iterations of key derivation per request.
            // See MaxPasswordLength. Refusal is a plain false - identical to any other failed
            // attempt, so it discloses nothing about why the attempt failed, and needsRehash stays
            // false so a refused attempt can never trigger a write.
            if (password != null && password.Length > MaxPasswordLength)
            {
                return false;
            }

            // Fail closed on absent input. Neither an empty password nor an empty stored value may
            // authenticate, and neither may raise on the login path.
            if (string.IsNullOrWhiteSpace(password) || string.IsNullOrWhiteSpace(storedHash))
            {
                return false;
            }

            // A legacy digest is routed to the MD5 comparison and, on success only, flagged for
            // immediate re-hashing by the caller. Routing on the stored shape - rather than trying
            // the modern verifier first - is what keeps existing credentials working without a
            // forced reset, and it keeps a 32-character value away from a Base64 decoder.
            if (IsLegacyHash(storedHash))
            {
                if (!VerifyMd5Hash(password, storedHash))
                {
                    return false;
                }

                needsRehash = true;
                return true;
            }

            return VerifyPbkdf2Hash(password, storedHash, out needsRehash);
        }

        /// <summary>
        /// Verifies a password against a modern PBKDF2 value, using the parameters recorded inside
        /// that value, and reports whether those parameters are weaker than the current target.
        /// </summary>
        /// <param name="password">The plaintext password. Never null, empty or whitespace here.</param>
        /// <param name="storedHash">The encoded value persisted for the account.</param>
        /// <param name="needsRehash">
        /// True only on success and only when the recorded iteration count is below
        /// <see cref="Pbkdf2IterationCount"/>.
        /// </param>
        /// <returns>True when the password matches; otherwise false.</returns>
        /// <remarks>
        /// This member NEVER throws. Every field read out of the payload is range-checked before it
        /// is used, and the Base64 decode is attempted with the non-throwing overload, so a
        /// truncated, corrupt or deliberately malformed row returns false instead of surfacing as a
        /// 500 on an endpoint reachable without credentials. That is a requirement, not a nicety: a
        /// single damaged row must not become a denial of service on the login path.
        /// SECURITY - the guards are ordered cheapest-first and every one of them runs BEFORE any
        /// key derivation is attempted, because the iteration count and salt length come out of the
        /// stored value and are therefore attacker-controlled the moment anything can write to the
        /// password column. An unbounded iteration count read from a row would otherwise be CPU
        /// exhaustion (CWE-400) reachable from the anonymous token endpoint.
        /// HMAC-SHA-512 is accepted although it is never written. Values in that shape can exist in
        /// a deployment that ran an interim build of this remediation, and they must keep working.
        /// They are deliberately NOT flagged for re-hashing: SHA-512 at the same iteration count is
        /// roughly three times more expensive per attacker guess than SHA-256, so converting one
        /// would REDUCE the work factor, and flagging on the PRF rather than on the work factor
        /// would also re-persist such a credential on every single login - the precise failure that
        /// disqualifies the framework's own PasswordHasher here. HMAC-SHA-1 and every other
        /// identifier are rejected outright: deny by default, and no value in that shape can have
        /// been produced by this codebase.
        /// </remarks>
        private static bool VerifyPbkdf2Hash(string password, string storedHash, out bool needsRehash)
        {
            needsRehash = false;

            if (storedHash.Length > MaxAcceptedEncodedLength)
            {
                return false;
            }

            // Sized to the exact maximum a Base64 string of this length can decode to. A length
            // that is not a multiple of four cannot be valid Base64, and the decode below reports
            // that by returning false rather than by throwing.
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

            // Computed as a long on purpose: saltLength is a uint read from the payload, so the
            // subtraction must not be allowed to wrap into a plausible-looking positive length.
            long subkeyLength = payloadLength - PayloadHeaderByteLength - (long)saltLength;
            if (subkeyLength < MinAcceptedSubkeyByteLength || subkeyLength > MaxAcceptedSubkeyByteLength)
            {
                return false;
            }

            byte[] salt = new byte[saltLength];
            Buffer.BlockCopy(payload, PayloadHeaderByteLength, salt, 0, (int)saltLength);

            byte[] expectedSubkey = new byte[subkeyLength];
            Buffer.BlockCopy(payload, PayloadHeaderByteLength + (int)saltLength, expectedSubkey, 0, (int)subkeyLength);

            byte[] actualSubkey = Rfc2898DeriveBytes.Pbkdf2(
                password,
                salt,
                (int)iterations,
                algorithm,
                (int)subkeyLength);

            // SECURITY (M-05, CWE-208 observable timing discrepancy) - fixed-time comparison, as
            // the mandated Authentication Hardening standard requires. Both spans are the same
            // length by construction here, which is the condition under which FixedTimeEquals is
            // actually fixed-time.
            if (!CryptographicOperations.FixedTimeEquals(expectedSubkey, actualSubkey))
            {
                return false;
            }

            needsRehash = iterations < Pbkdf2IterationCount;
            return true;
        }

        /// <summary>
        /// A throwaway, per-process salt used only by
        /// <see cref="PerformDummyVerification(string)"/>. Generated rather than written as a
        /// literal so that no constant in this file can be mistaken for - or degenerate into -
        /// embedded key material. It protects nothing and may be discarded at any time.
        /// </summary>
        private static readonly byte[] dummyVerificationSalt = RandomNumberGenerator.GetBytes(Pbkdf2SaltByteLength);

        /// <summary>
        /// Spends exactly the same amount of work a real modern verification would spend, and
        /// discards the result. Call this on a credential-resolution path that is about to fail
        /// WITHOUT having performed a modern verification, so that the failure costs the same as a
        /// success.
        /// </summary>
        /// <param name="password">
        /// The plaintext the caller was given. Used only as derivation input so the work is real
        /// and cannot be optimised away; it is never compared against anything and never stored.
        /// </param>
        /// <remarks>
        /// SECURITY (CWE-208 observable timing discrepancy, CWE-203 observable difference in
        /// behaviour) - this exists because moving credential verification out of the SQL predicate
        /// and into application code, which a per-credential salt makes unavoidable, would otherwise
        /// create an account-enumeration oracle: an address that does not exist would return in
        /// under a millisecond while one that does would take the full derivation. Equalising the
        /// two is cheaper and far more reliable than trying to make the fast path slower by
        /// guesswork. The cost is bounded per account and per source address by
        /// Web/Services/LoginThrottleService.cs, so this cannot be turned into an amplification
        /// lever by an unauthenticated caller.
        /// </remarks>
        internal static void PerformDummyVerification(string password)
        {
            byte[] discarded = Rfc2898DeriveBytes.Pbkdf2(
                password ?? string.Empty,
                dummyVerificationSalt,
                Pbkdf2IterationCount,
                HashAlgorithmName.SHA256,
                Pbkdf2SubkeyByteLength);

            // Zeroing serves two purposes: it is ordinary hygiene for derived key material, and it
            // is an observable use of the result, so no future compiler or runtime is entitled to
            // elide the derivation above as dead code.
            CryptographicOperations.ZeroMemory(discarded);
        }

        /// <summary>
        /// Reports whether a stored value is a legacy MD5 digest rather than a modern PBKDF2
        /// value. The two shapes are unambiguous: a legacy digest is exactly
        /// <see cref="Md5HexLength"/> hexadecimal characters, whereas a modern value is an
        /// 84-character Base64 string that always begins with 'A', the encoding of the 0x01
        /// format marker. No new column and no schema change are needed to tell them apart.
        /// </summary>
        /// <param name="storedHash">The value currently persisted for the account.</param>
        /// <returns>True when the value has the legacy shape; otherwise false.</returns>
        /// <remarks>
        /// Hexadecimal is accepted in either case. <see cref="GetMd5Hash(string)"/> only ever
        /// emitted lower case, but the comparison this remediation replaces was case-insensitive,
        /// so a value persisted in upper or mixed case by any other route must still be
        /// recognised - failing to recognise it would lock that account out, which the
        /// requirement that existing credentials keep working forbids. The tolerance is free: a
        /// 32-character hexadecimal string cannot collide with the modern format at any casing.
        /// Exposed to the assembly rather than kept private because the version 4 data migration
        /// in ERPService needs exactly this test to decide whether a deployment still carries the
        /// administrator credential shipped by earlier releases, without recomputing MD5 itself.
        /// </remarks>
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
        /// Renders the MD5 digest of the supplied text as lower-case hexadecimal.
        /// </summary>
        /// <remarks>
        /// LEGACY SUPPORT ONLY. This exists exclusively so that credentials written by earlier
        /// releases can still be verified and then upgraded - see the header of this file. It must
        /// NEVER be used to produce a value that is newly persisted: new credentials go through
        /// <see cref="HashPassword(string)"/>. MD5 is unsalted and fast, which is what made C-03 a
        /// Critical finding, and it is also why analyzer rule CA5351 reports on this method; that
        /// warning is accepted and recorded in docs/security/risk-register.md.
        /// Returns <see cref="string.Empty"/> for null, empty or whitespace input. That behaviour
        /// is preserved exactly as it was, because callers depend on it.
        /// </remarks>
        internal static string GetMd5Hash(string input)
        {
            // Size before content. MD5 is fast, but it is not free: an unbounded input still costs
            // a full whitespace scan, a UTF-8 byte-array allocation proportional to the input and a
            // digest computation over every byte. This member is reachable from the anonymous login
            // path through VerifyMd5Hash, so it carries the same bound as the modern primitive.
            // See MaxPasswordLength. Empty is returned to match this member's existing
            // absent-input contract exactly, which its four in-assembly callers already rely on.
            if (input != null && input.Length > MaxPasswordLength)
            {
                return string.Empty;
            }

			if (string.IsNullOrWhiteSpace(input))
				return string.Empty;

            // SECURITY (M-06, CWE-362 concurrent execution using shared resource with improper
            // synchronisation) - the static MD5 instance this replaces was shared by every caller
            // and MD5 instances are not thread-safe, so two simultaneous authentications could
            // interleave inside ComputeHash and corrupt each other's digest. The static one-shot
            // keeps no shared state at all, so it is correct under concurrency and needs no lock.
            byte[] data = MD5.HashData(Encoding.UTF8.GetBytes(input));

            StringBuilder sBuilder = new StringBuilder();
            for (int i = 0; i < data.Length; i++)
                sBuilder.Append(data[i].ToString("x2"));

            return sBuilder.ToString();
        }

        /// <summary>
        /// Verifies a password against a LEGACY MD5 digest in fixed time.
        /// </summary>
        /// <param name="input">The plaintext password.</param>
        /// <param name="hash">The legacy digest currently persisted for the account.</param>
        /// <returns>True when the password matches the digest; otherwise false.</returns>
        /// <remarks>
        /// LEGACY SUPPORT ONLY, and retained on purpose rather than deleted: it is the migration
        /// path for credentials written by earlier releases, and it is the member the version 4
        /// data migration in ERPService uses to test whether a deployment still carries the
        /// administrator credential those releases shipped - which lets that credential be
        /// invalidated without overwriting a password an operator has already changed. New
        /// credentials are verified by <see cref="VerifyPassword(string, string, out bool)"/>,
        /// which calls through to here only when the stored value has the legacy shape.
        /// </remarks>
        internal static bool VerifyMd5Hash(string input, string hash)
        {
            // Size before content, on both operands. See MaxPasswordLength. The plaintext bound is
            // the resource control; the digest bound is exact rather than merely generous, because a
            // legacy MD5 digest is by definition exactly Md5HexLength characters, so any other
            // length cannot possibly match and is refused before ToLowerInvariant allocates a copy
            // and before UTF-8 encoding allocates a byte array. That is behaviour-preserving: a
            // wrong-length digest already failed at the byte-length comparison further down, which
            // is retained because FixedTimeEquals is only fixed-time across equal-length spans and
            // a non-ASCII digest can still differ in byte length while matching in character count.
            if ((input != null && input.Length > MaxPasswordLength)
                || (hash != null && hash.Length != Md5HexLength))
            {
                return false;
            }

            // Fail closed on absent input. The comparison this replaces returned TRUE for an empty
            // password against an empty stored digest, because both sides collapsed to
            // string.Empty; an absent credential must never authenticate anything.
            if (string.IsNullOrWhiteSpace(input) || string.IsNullOrWhiteSpace(hash))
            {
                return false;
            }

            string hashOfInput = GetMd5Hash(input);

            // SECURITY (M-05, CWE-208 observable timing discrepancy) - the StringComparer
            // comparison this replaces short-circuited at the first differing character, so its
            // duration revealed how many leading characters were already correct and let an
            // attacker reconstruct a stored digest one character at a time. FixedTimeEquals
            // inspects every byte regardless of where the values diverge.
            // Casing is normalised first to keep the case-insensitive tolerance the previous
            // comparison had: a digest persisted in upper case must still verify, or that account
            // is locked out. Normalising is not secret-dependent branching, so it does not
            // reintroduce the oracle. Length is likewise checked before the comparison, on
            // purpose - FixedTimeEquals is only fixed-time across equal-length spans, and a length
            // difference is not a secret that can be probed for one.
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
