#region <--- DIRECTIVES --->
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

#endregion

namespace WebVella.Erp.Utilities
{
    public class CryptoUtility
    {
        #region <--- Fields --->

        // SECURITY (C-04, CWE-798 hard-coded credentials / CWE-321 hard-coded cryptographic key, OWASP
        // A02:2021) - this class holds NO default encryption key, and none may be added. A compiled-in default
        // is public knowledge twice over: this assembly ships to nuget.org, so the constant is readable straight
        // out of the library, and the same literal shipped in every Config.json - so a deployment that supplied
        // no key of its own encrypted with a key an attacker already held, unrotatable because every deployment
        // shared it. INVARIANT: absent key configuration fails fast (see CryptKey below). A constant without a
        // fallback, or a fallback without a constant, each leave the defect in place - both must stay absent.

        // Caches the encryption key after the first SUCCESSFUL resolution. The configured key is the only value ever
        // stored here.
        private static string cryptKey;

        #endregion

        #region <--- Properties --->

        public static string CryptKey
        {
            get
            {
                if (string.IsNullOrEmpty(cryptKey))
                {
                    // SECURITY (C-04, CWE-798/CWE-321, OWASP A02:2021) - a caller reaching this property with no key
                    // configured is stopped loudly rather than handed a predictable key it would mistake for protection.
                    // There is deliberately no development-mode escape hatch, which would reintroduce the defect, and no
                    // generated random key, which would silently make already-encrypted data undecryptable.
                    if (string.IsNullOrWhiteSpace(ErpSettings.EncryptionKey))
                    {
                        // Only configuration key NAMES appear below. The value, any prefix of it, its length and any
                        // digest of it are all withheld, so this failure cannot leak key material into a console, a
                        // log file or a crash report (CWE-532).
                        throw new InvalidOperationException(
                            "WebVella ERP cannot encrypt or decrypt data: required security configuration " +
                            "'Settings:EncryptionKey' is missing. Supply it through the 'Settings__EncryptionKey' " +
                            "environment variable, or in Config.json - the legacy misspelled " +
                            "'Settings:EncriptionKey' spelling is still honoured. No compiled-in default " +
                            "encryption key exists, by design (OWASP Top 10 finding C-04 - CWE-798, CWE-321), " +
                            "and no insecure fallback remains. See docs/security/secure-configuration.md for the " +
                            "supported supply channels and for how a deployment that relied on a removed default " +
                            "keeps its existing encrypted data readable.");
                    }

                    // The configured key is the ONLY value this property will ever cache or return.
                    cryptKey = ErpSettings.EncryptionKey;
                }
                return cryptKey;
            }
        }

        #endregion

        #region <--- Methods --->

        /// <summary>
        /// 	Encrypts the text with the configured key resolved through <see cref="CryptKey"/>, which throws
        /// 	rather than falling back to a compiled-in default when none is configured (C-04).
        /// </summary>
        /// <param name="text"> The text. </param>
        /// <param name="algorithm"> The algorithm. </param>
        /// <returns> </returns>
        public static string EncryptText(string text, SymmetricAlgorithm algorithm)
        {
            return EncryptText(text, CryptKey, algorithm);
        }

        /// <summary>
        /// 	Decrypts the cypher text with the configured key resolved through <see cref="CryptKey"/>, which
        /// 	throws rather than falling back to a compiled-in default when none is configured (C-04).
        /// </summary>
        /// <param name="cypherText"> The cypher text. </param>
        /// <param name="algorithm"> The algorithm. </param>
        /// <returns> </returns>
        public static string DecryptText(string cypherText, SymmetricAlgorithm algorithm)
        {
            return DecryptText(cypherText, CryptKey, algorithm);
        }

        /// <summary>
        /// 	Encrypts the input data with the configured key resolved through <see cref="CryptKey"/>, which
        /// 	throws rather than falling back to a compiled-in default when none is configured (C-04).
        /// </summary>
        /// <param name="inputData"> The input data. </param>
        /// <param name="algorithm"> The algorithm. </param>
        /// <returns> </returns>
        public static byte[] EncryptData(byte[] inputData, SymmetricAlgorithm algorithm)
        {
            return EncryptData(inputData, CryptKey, algorithm);
        }

        /// <summary>
        /// 	Decrypts the input data with the configured key resolved through <see cref="CryptKey"/>, which
        /// 	throws rather than falling back to a compiled-in default when none is configured (C-04).
        /// </summary>
        /// <param name="inputData"> The input data. </param>
        /// <param name="algorithm"> The algorithm. </param>
        /// <returns> </returns>
        public static byte[] DecryptData(byte[] inputData, SymmetricAlgorithm algorithm)
        {
            return DecryptData(inputData, CryptKey, algorithm);
        }

        /// <summary>
        /// 	Encrypts the text.
        /// </summary>
        /// <param name="text"> The text. </param>
        /// <param name="key"> The key. </param>
        /// <param name="algorithm"> The algorithm. </param>
        /// <returns> </returns>
        public static string EncryptText(string text, string key, SymmetricAlgorithm algorithm)
        {
            algorithm.Key = GetValidKey(key, algorithm);
            algorithm.IV = GetValidIV(key, algorithm.IV.Length);

            byte[] buffer = EncryptInternal(text, algorithm);
            return Convert.ToBase64String(buffer);
        }

        /// <summary>
        /// 	Decrypts the text.
        /// </summary>
        /// <param name="cypherText"> The cypher text. </param>
        /// <param name="key"> The key. </param>
        /// <param name="algorithm"> The algorithm. </param>
        /// <returns> </returns>
        public static string DecryptText(string cypherText, string key, SymmetricAlgorithm algorithm)
        {
            algorithm.Key = GetValidKey(key, algorithm);
            algorithm.IV = GetValidIV(key, algorithm.IV.Length);

            byte[] inputBuffer = Convert.FromBase64String(cypherText);
            return DecryptInternal(inputBuffer, algorithm);
        }

        /// <summary>
        /// 	Encrypts the text.
        /// </summary>
        /// <param name="data"> The data. </param>
        /// <param name="key"> The key. </param>
        /// <param name="algorithm"> The algorithm. </param>
        /// <returns> </returns>
        public static byte[] EncryptData(byte[] data, string key, SymmetricAlgorithm algorithm)
        {
            algorithm.Key = GetValidKey(key, algorithm);
            algorithm.IV = GetValidIV(key, algorithm.IV.Length);

            return EncryptDataInternal(data, algorithm);
        }

        /// <summary>
        /// 	Decrypts the text.
        /// </summary>
        /// <param name="data"> The data. </param>
        /// <param name="key"> The key. </param>
        /// <param name="algorithm"> The algorithm. </param>
        /// <returns> </returns>
        public static byte[] DecryptData(byte[] data, string key, SymmetricAlgorithm algorithm)
        {
            algorithm.Key = GetValidKey(key, algorithm);
            algorithm.IV = GetValidIV(key, algorithm.IV.Length);

            return DecryptDataInternal(data, algorithm);
        }

        /// <summary>
        /// 	Computes MD5 hash value for specified input string
        /// </summary>
        /// <param name="inputString"> The input string. </param>
        /// <returns> </returns>
        public static string ComputeMD5Hash(string inputString)
        {
            byte[] bytes = (new UnicodeEncoding()).GetBytes(inputString);
            byte[] hashValue = (MD5.Create()).ComputeHash(bytes);
            return BitConverter.ToString(hashValue);
        }

        /// <summary>
        /// 	Computes the MD5 hash.
        /// </summary>
        /// <param name="inputString"> The input string. </param>
        /// <returns> </returns>
        public static byte[] ComputeMD5HashBytes(string inputString)
        {
            byte[] bytes = (new UnicodeEncoding()).GetBytes(inputString);
            return (MD5.Create()).ComputeHash(bytes);
        }

        /// <summary>
        /// 	Computes the odd M d5 hash.
        /// </summary>
        /// <param name="str"> The STR. </param>
        /// <returns> </returns>
        public static string ComputeOddMD5Hash(string str)
        {
            MD5 md5 = MD5.Create();
            byte[] dataMd5 = md5.ComputeHash(Encoding.Unicode.GetBytes(str));
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < dataMd5.Length; i++)
                sb.AppendFormat("{0:x2}", dataMd5[i]);
            return sb.ToString();
        }

        /// <summary>
        /// 	Computes the PHP like M d5 hash.
        /// </summary>
        /// <param name="text"> The text. </param>
        /// <returns> </returns>
        public static string ComputePhpLikeMD5Hash(string text)
        {
            byte[] textBytes = Encoding.Default.GetBytes(text);

            var cryptHandler = MD5.Create();
            byte[] hash = cryptHandler.ComputeHash(textBytes);
            string ret = "";
            foreach (byte a in hash)
            {
                if (a < 16)
                    ret += "0" + a.ToString("x");
                else
                    ret += a.ToString("x");
            }
            return ret;
        }

        #endregion

        #region <--- Private Methods --->

        // SECURITY NOTE (M-08, CWE-329, OWASP A02:2021) - DOCUMENTED ONLY, DELIBERATELY NOT CHANGED HERE.
        // The key and initialisation-vector derivation below is deterministic - the vector is derived from the
        // key itself, so the same plaintext always produces the same ciphertext. It is latent, the symmetric
        // encrypt/decrypt API having no in-repository callers, and changing the derivation or moving to an
        // authenticated cipher mode would make every already-persisted ciphertext undecryptable, which the
        // preservation requirement forbids. Accepted as RISK-006 in docs/security/risk-register.md, which
        // carries the recommended fix. CA5390, CA5401 and the CA5351 diagnostics on the MD5 derivation below
        // describe this code and are intentionally left as warnings.

        /// <summary>
        /// 	Projects key or initialisation-vector material to bytes, refusing any character outside US-ASCII
        /// 	instead of silently substituting it.
        /// </summary>
        /// <param name="material"> The key or initialisation-vector text actually about to be consumed. </param>
        /// <param name="materialName"> Names which material failed, for the diagnostic only. Never the value. </param>
        /// <returns> The US-ASCII bytes of <paramref name="material"/>. </returns>
        private static byte[] ToAsciiKeyMaterial(string material, string materialName)
        {
            // THREAT ADDRESSED - CWE-331 (insufficient entropy) with CWE-176 (improper handling of Unicode
            // encoding), OWASP A02:2021. Both derivation helpers below called Encoding.ASCII.GetBytes directly,
            // and that encoder does not fail on input it cannot represent - it SUBSTITUTES, mapping every
            // character above U+007F to '?' (0x3F). The consequence was measured: a 32-character key of 32
            // DISTINCT non-ASCII characters derived to 3f repeated 32 times, so the AES key was predictable from
            // the key's SHAPE alone, two different keys derived identical bytes, and the initialisation vector -
            // derived from the same text - collided too. An ordinary accented passphrase lost one byte of key
            // material per accent. Failing is the point: the alternative is not a lesser key but one an attacker
            // can reconstruct without seeing it. Only the material's ROLE is named - never its value, length, the
            // offending character or its position (CWE-532).
            for (int index = 0; index < material.Length; index++)
            {
                if (material[index] > 0x7f)
                {
                    throw new InvalidOperationException(
                        $"WebVella ERP cannot derive cryptographic {materialName} material: the supplied value " +
                        "contains at least one character outside US-ASCII. Such characters cannot be represented " +
                        "by the ASCII projection this derivation uses and were previously replaced with '?', " +
                        "which silently destroyed key entropy (CWE-331, CWE-176). " +
                        "Supply US-ASCII key material only - printable ASCII letters, digits and " +
                        "symbols. When 'Settings:EncryptionKey' is the source, startup validation reports this " +
                        "before any data is touched. See docs/security/secure-configuration.md for the accepted " +
                        "character set, and docs/security/risk-register.md for how a deployment that already " +
                        "encrypted data under a non-ASCII key recovers it.");
                }
            }

            return Encoding.ASCII.GetBytes(material);
        }

        /// <summary>
        /// 	Gets the valid encode key.
        /// </summary>
        /// <param name="key"> The key. </param>
        /// <param name="encodeMethod"> The encode method. </param>
        /// <returns> </returns>
        private static byte[] GetValidKey(string key, SymmetricAlgorithm encodeMethod)
        {
            string result;
            if (encodeMethod.LegalKeySizes.Length > 0)
            {
                int size = encodeMethod.LegalKeySizes[0].MinSize;

                // key sizes are in bits
                while (key.Length * 8 > size &&
                       encodeMethod.LegalKeySizes[0].SkipSize > 0 &&
                       size < encodeMethod.LegalKeySizes[0].MaxSize)
                    size += encodeMethod.LegalKeySizes[0].SkipSize;

                result = key.Length * 8 > size ? key.Substring(0, (size / 8)) : key.PadRight(size / 8, ' ');
            }
            else
                result = key;

            // The sizing above measures CHARACTERS while the projection below consumes BYTES; refusing non-ASCII
            // material is what makes the two agree, because for US-ASCII input one character is exactly one byte -
            // so this is byte-identical to the previous Encoding.ASCII.GetBytes for every key that already worked.
            return ToAsciiKeyMaterial(result, "key");
        }

        /// <summary>
        /// 	Gets the valid encode IV.
        /// </summary>
        /// <param name="InitVector"> The init vector. </param>
        /// <param name="ValidLength"> Length of the valid. </param>
        /// <returns> </returns>
        private static byte[] GetValidIV(String InitVector, int ValidLength)
        {
            // The vector is derived from the key text, so it inherited the same silent substitution -
            // a non-ASCII key produced an all-'?' vector that collided across different keys. The pad character
            // is a space, which is itself ASCII, so padding never introduces material this guard would refuse.
            if (InitVector.Length > ValidLength)
                return ToAsciiKeyMaterial(InitVector.Substring(0, ValidLength), "initialisation vector");

            return ToAsciiKeyMaterial(InitVector.PadRight(ValidLength, ' '), "initialisation vector");
        }

        /// <summary>
        /// 	Encrypts the specified plain text.
        /// </summary>
        /// <param name="text"> The plain text. </param>
        /// <param name="algorithm"> The algorithm. </param>
        /// <returns> </returns>
        private static byte[] EncryptInternal(string text, SymmetricAlgorithm algorithm)
        {
            MemoryStream ms = new MemoryStream();
            CryptoStream encStream = new CryptoStream(ms, algorithm.CreateEncryptor(), CryptoStreamMode.Write);

            StreamWriter sw = new StreamWriter(encStream);
            sw.WriteLine(text);
            sw.Close();
            encStream.Close();

            byte[] buffer = ms.ToArray();
            ms.Close();

            return buffer;
        }

        /// <summary>
        /// 	Decrypts the specified cypher text.
        /// </summary>
        /// <param name="cypherText"> The cypher text. </param>
        /// <param name="algorithm"> The algorithm. </param>
        /// <returns> </returns>
        private static string DecryptInternal(byte[] cypherText, SymmetricAlgorithm algorithm)
        {
            MemoryStream ms = new MemoryStream(cypherText);
            CryptoStream encStream = new CryptoStream(ms, algorithm.CreateDecryptor(), CryptoStreamMode.Read);
            StreamReader sr = new StreamReader(encStream);

            string val = sr.ReadLine();
            sr.Close();
            encStream.Close();
            ms.Close();

            return val;
        }

        /// <summary>
        /// 	Encrypts the specified plain text.
        /// </summary>
        /// <param name="data"> The data. </param>
        /// <param name="algorithm"> The algorithm. </param>
        /// <returns> </returns>
        private static byte[] EncryptDataInternal(byte[] data, SymmetricAlgorithm algorithm)
        {
            MemoryStream ms = new MemoryStream();
            CryptoStream encStream = new CryptoStream(ms, algorithm.CreateEncryptor(), CryptoStreamMode.Write);
            encStream.Write(data, 0, data.Length);
            encStream.Close();

            byte[] buffer = ms.ToArray();

            return buffer;
        }

        /// <summary>
        /// 	Decrypts the specified cypher text.
        /// </summary>
        /// <param name="inputData"> The input data. </param>
        /// <param name="algorithm"> The algorithm. </param>
        /// <returns> </returns>
        private static byte[] DecryptDataInternal(byte[] inputData, SymmetricAlgorithm algorithm)
        {
            MemoryStream ms = new MemoryStream(inputData);
            CryptoStream encStream = new CryptoStream(ms, algorithm.CreateDecryptor(), CryptoStreamMode.Read);
            BinaryReader br = new BinaryReader(encStream);
            List<byte> data = new List<byte>();

            byte[] buffer;
            while ((buffer = br.ReadBytes(2048)).Length > 0)
                data.AddRange(buffer);
            encStream.Close();
            ms.Close();

            return data.ToArray();
        }

        #endregion
    }
}
