using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Dependencies.Security
{
    internal class AESEncryption
    {
        public static string Encrypt(string text, string passphrase)
        {
            // Generate a random salt
            byte[] saltBytes = new byte[16];
            using (RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider())
            {
                rngCsp.GetBytes(saltBytes);
            }

            // Derive a key using PBKDF2
            using (Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(passphrase, saltBytes, 10000))
            {
                byte[] keyBytes = pbkdf2.GetBytes(32); // 256 bits key
                byte[] ivBytes = pbkdf2.GetBytes(16);  // 128 bits IV

                using (Aes aesAlg = Aes.Create())
                {
                    aesAlg.Key = keyBytes;
                    aesAlg.IV = ivBytes;
                    aesAlg.Mode = CipherMode.CBC;
                    aesAlg.Padding = PaddingMode.PKCS7;

                    using (MemoryStream msEncrypt = new MemoryStream())
                    {
                        using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, aesAlg.CreateEncryptor(), CryptoStreamMode.Write))
                        {
                            using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                            {
                                swEncrypt.Write(text);
                            }
                        }

                        // Combine salt, IV, and ciphertext into a single byte array
                        byte[] saltPlusIVPlusCipherText = new byte[saltBytes.Length + ivBytes.Length + msEncrypt.ToArray().Length];
                        Buffer.BlockCopy(saltBytes, 0, saltPlusIVPlusCipherText, 0, saltBytes.Length);
                        Buffer.BlockCopy(ivBytes, 0, saltPlusIVPlusCipherText, saltBytes.Length, ivBytes.Length);
                        Buffer.BlockCopy(msEncrypt.ToArray(), 0, saltPlusIVPlusCipherText, saltBytes.Length + ivBytes.Length, msEncrypt.ToArray().Length);

                        // Convert the result to Base64
                        string encryptedText = Convert.ToBase64String(saltPlusIVPlusCipherText);

                        return encryptedText;
                    }
                }
            }
        }

        public static string Decrypt(string encryptedText, string passphrase)
        {
            // Convert the Base64 string back to bytes
            byte[] saltPlusIVPlusCipherText = Convert.FromBase64String(encryptedText);

            // Extract the salt and IV
            byte[] saltBytes = new byte[16];
            byte[] ivBytes = new byte[16];
            byte[] cipherTextBytes = new byte[saltPlusIVPlusCipherText.Length - 32];

            Buffer.BlockCopy(saltPlusIVPlusCipherText, 0, saltBytes, 0, 16);
            Buffer.BlockCopy(saltPlusIVPlusCipherText, 16, ivBytes, 0, 16);
            Buffer.BlockCopy(saltPlusIVPlusCipherText, 32, cipherTextBytes, 0, saltPlusIVPlusCipherText.Length - 32);

            // Derive the key using PBKDF2
            using (Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(passphrase, saltBytes, 10000))
            {
                byte[] keyBytes = pbkdf2.GetBytes(32); // 256 bits key

                using (Aes aesAlg = Aes.Create())
                {
                    aesAlg.Key = keyBytes;
                    aesAlg.IV = ivBytes;
                    aesAlg.Mode = CipherMode.CBC;
                    aesAlg.Padding = PaddingMode.PKCS7;

                    using (MemoryStream msDecrypt = new MemoryStream(cipherTextBytes))
                    {
                        using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, aesAlg.CreateDecryptor(), CryptoStreamMode.Read))
                        {
                            using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                            {
                                string decryptedText = srDecrypt.ReadToEnd();
                                return decryptedText;
                            }
                        }
                    }
                }
            }
        }
    }
}
