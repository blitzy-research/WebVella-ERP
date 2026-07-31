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

        // SECURITY (C-04, CWE-798/CWE-321, OWASP A02:2021) - Cryptographic Failures.
        // A 64-hex-character default encryption key used to be compiled in at this position. It has been DELETED.
        // THREAT: the value was public knowledge twice over. This assembly is published to nuget.org as package
        // WebVella.Erp, so anyone could read the constant out of the shipped library, and the identical literal was
        // additionally shipped in all eight Config.json files. Every installation that never supplied its own key
        // therefore encrypted with a key an attacker already held, and that key could be neither rotated nor
        // revoked because it was the same for every deployment.
        // No replacement default is provided, by design: the CryptKey property below now fails fast. Deleting only
        // the constant while leaving a fallback in place would have relocated the defect instead of fixing it.

        // Caches the encryption key after the first SUCCESSFUL resolution. Pre-existing behaviour, deliberately
        // retained: it is unrelated to C-04 and the only value ever stored here is the configured key.
        private static string cryptKey;

        #endregion

        #region <--- Properties --->

        public static string CryptKey
        {
            get
            {
                if (string.IsNullOrEmpty(cryptKey))
                {
                    // SECURITY (C-04, CWE-798/CWE-321, OWASP A02:2021) - fail fast replaces a silent fallback to a
                    // compiled-in key. Removing only the constant would have relocated the defect, not fixed it: a
                    // caller that reaches this property with no key configured must be stopped loudly rather than
                    // handed a predictable key it would then mistake for protection. There is deliberately NO
                    // development-mode or environment escape hatch, because that would recreate the very defect
                    // being removed, and deliberately NO generated random key, because that would silently make
                    // already-encrypted data undecryptable - a worse outcome than failing loudly.
                    if (string.IsNullOrWhiteSpace(ErpSettings.EncryptionKey))
                    {
                        // Only configuration key NAMES appear below. The value, any prefix of it, its length and any
                        // digest of it are all withheld, so this failure cannot leak key material into a console, a
                        // log file or a crash report (CWE-532).
                        throw new InvalidOperationException(
                            "WebVella ERP cannot encrypt or decrypt data: required security configuration " +
                            "'Settings:EncryptionKey' is missing. Supply it through the 'Settings__EncryptionKey' " +
                            "environment variable, through user secrets in development, or in Config.json - the " +
                            "legacy mispelled 'Settings:EncriptionKey' spelling is still honoured. The compiled-in " +
                            "default encryption key was removed on purpose by the OWASP Top 10 remediation " +
                            "(finding C-04 - CWE-798, CWE-321) and no insecure fallback remains by design. " +
                            "See docs/security/secure-configuration.md, which also covers how a deployment that " +
                            "previously relied on the removed default keeps its existing encrypted data readable.");
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
        /// 	Encrypts the text using default related key
        /// </summary>
        /// <param name="text"> The text. </param>
        /// <param name="algorithm"> The algorithm. </param>
        /// <returns> </returns>
        public static string EncryptText(string text, SymmetricAlgorithm algorithm)
        {
            return EncryptText(text, CryptKey, algorithm);
        }

        /// <summary>
        /// 	Decrypts the text using machine related key
        /// </summary>
        /// <param name="cypherText"> The cypher text. </param>
        /// <param name="algorithm"> The algorithm. </param>
        /// <returns> </returns>
        public static string DecryptText(string cypherText, SymmetricAlgorithm algorithm)
        {
            return DecryptText(cypherText, CryptKey, algorithm);
        }

        /// <summary>
        /// 	Encrypts the text using default related key
        /// </summary>
        /// <param name="inputData"> The input data. </param>
        /// <param name="algorithm"> The algorithm. </param>
        /// <returns> </returns>
        public static byte[] EncryptData(byte[] inputData, SymmetricAlgorithm algorithm)
        {
            return EncryptData(inputData, CryptKey, algorithm);
        }

        /// <summary>
        /// 	Decrypts the text using machine related key
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
        // The key and initialisation-vector derivation helpers in this region are deterministic: the vector is
        // derived from the key itself, so the same plaintext always produces the same ciphertext. That is a Medium
        // finding under the audit's severity matrix, it is latent (the symmetric encrypt/decrypt API has no
        // in-repository callers), and the remediation scope fixes Critical and High findings only. Changing the
        // derivation or moving to an authenticated cipher mode would also make every already-persisted ciphertext
        // undecryptable, which the "all existing functionality remains operational" preservation requirement
        // forbids. Tracked as an accepted risk in docs/security/risk-register.md; any CA5389/CA5390/CA5401
        // analyzer diagnostic on the code below is expected and intentionally left as a warning.

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

            return Encoding.ASCII.GetBytes(result);
        }

        /// <summary>
        /// 	Gets the valid encode IV.
        /// </summary>
        /// <param name="InitVector"> The init vector. </param>
        /// <param name="ValidLength"> Length of the valid. </param>
        /// <returns> </returns>
        private static byte[] GetValidIV(String InitVector, int ValidLength)
        {
            if (InitVector.Length > ValidLength)
                return Encoding.ASCII.GetBytes(InitVector.Substring(0, ValidLength));

            return Encoding.ASCII.GetBytes(InitVector.PadRight(ValidLength, ' '));
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
