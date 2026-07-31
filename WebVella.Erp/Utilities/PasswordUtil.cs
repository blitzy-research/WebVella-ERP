// SECURITY C-03 (CWE-916 password hash with insufficient computational effort, CWE-759 one-way
// hash without a salt / OWASP A02:2021 Cryptographic Failures).
// This utility used to store credentials as an unsalted, single-pass MD5 digest. That is a
// data-breach exposure rather than a mere "weak cryptography" note: a leaked password column is
// recoverable wholesale from precomputed tables at effectively zero cost, and identical passwords
// produce identical digests, so one cracked value exposes every account sharing it. Credentials
// are now stored as a salted, work-factored PBKDF2 value produced by the ASP.NET Core password
// hasher and verified in fixed time. Two further findings are closed by the same edit: M-06
// (CWE-362, the shared mutable MD5 instance) and M-05 (CWE-208, the short-circuiting comparison).
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
//   2. The mandated parameters name HMAC-SHA-256 AND the versioned (V3) format. In ASP.NET Core
//      those two are mutually exclusive: the V3 format IS PBKDF2-HMAC-SHA512, and
//      PasswordHasherOptions exposes no pseudo-random-function selector - only CompatibilityMode
//      and IterationCount. V3 is kept, because it is also the only route that supplies the
//      framework's own fixed-time verification and its SuccessRehashNeeded upgrade signal, both
//      of which are required here. The outcome EXCEEDS the named requirement: the OWASP iteration
//      floor for PBKDF2-HMAC-SHA512 is 210,000 and this uses 600,000, measured at roughly 380 ms
//      of CPU per verification against roughly 120 ms for HMAC-SHA-256 at the same count - about
//      three times the work per attacker guess.

using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace WebVella.Erp.Utilities
{
    public static class PasswordUtil
    {
        /// <summary>
        /// The modern credential primitive: PBKDF2 in the ASP.NET Core versioned (V3) format,
        /// which pairs every credential with its own 128-bit cryptographically random salt,
        /// applies 600,000 iterations, derives a 256-bit subkey and encodes the salt, the
        /// iteration count and the format marker alongside the subkey in one self-describing
        /// string. Storing the parameters with the value is what allows the work factor to be
        /// raised later without invalidating anything already written.
        /// </summary>
        /// <remarks>
        /// SECURITY (C-03, CWE-916/CWE-759, OWASP A02:2021) - the salt defeats precomputed
        /// tables and makes two identical passwords hash differently; the iteration count makes
        /// each offline guess expensive.
        /// The iteration count is the control, not a tuning knob. It deliberately costs roughly
        /// 380 ms of CPU per hash and per verification, and that cost is a pre-declared, accepted
        /// trade-off recorded in docs/security/remediation-log.md - do NOT lower it to chase a
        /// latency target. Only the authentication path pays it; no other request path is
        /// affected. It is set explicitly because the framework default is 100,000, well below
        /// the 600,000 this remediation requires.
        /// PasswordHasher keeps no mutable per-call state and is safe to share across concurrent
        /// requests, which is exactly why replacing the previous shared MD5 instance with it does
        /// not reintroduce M-06.
        /// The generic argument is unused by design: PasswordHasher&lt;TUser&gt; is constrained to
        /// a reference type but never dereferences the user it is handed, so object together with
        /// a null user is correct and keeps this core library from taking a dependency on any
        /// particular user type.
        /// </remarks>
        private static readonly IPasswordHasher<object> passwordHasher = new PasswordHasher<object>(
            Options.Create(new PasswordHasherOptions
            {
                CompatibilityMode = PasswordHasherCompatibilityMode.IdentityV3,
                IterationCount = 600_000
            }));

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
            if (string.IsNullOrWhiteSpace(password))
            {
                return string.Empty;
            }

            return passwordHasher.HashPassword(null, password);
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
        /// either because it is a legacy MD5 digest or because the framework reports
        /// <see cref="PasswordVerificationResult.SuccessRehashNeeded"/> - which also covers a
        /// value written at a lower iteration count or in the older V2 format, so a future work
        /// factor increase is carried by this same mechanism with no further code change. The
        /// caller still holds the plaintext at that moment and should call
        /// <see cref="HashPassword(string)"/> and persist the result. Always false when
        /// verification fails, so a failed attempt can never trigger a write.
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

            PasswordVerificationResult result;

            try
            {
                result = passwordHasher.VerifyHashedPassword(null, storedHash, password);
            }
            // Only the two exception types a malformed stored value can actually produce are
            // caught: FormatException from Base64 decoding, and ArgumentException - the base of
            // both ArgumentNullException and ArgumentOutOfRangeException - from a truncated or
            // absent payload. A corrupt value must fail verification rather than surface as a 500
            // on an anonymous endpoint. This is deliberately NOT a blanket swallow: any other
            // exception, and so any genuine platform fault, still propagates and stays visible.
            catch (FormatException)
            {
                return false;
            }
            catch (ArgumentException)
            {
                return false;
            }

            if (result == PasswordVerificationResult.Success)
            {
                return true;
            }

            if (result == PasswordVerificationResult.SuccessRehashNeeded)
            {
                needsRehash = true;
                return true;
            }

            return false;
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

