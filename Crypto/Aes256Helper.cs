using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CryptoNet
{
    public class Aes256Helper
    {
        protected byte[] GenerateKey()
        {
            using (var aes = CreateAes256Algorithm())
            {
                aes.GenerateKey();
                return aes.Key;
            }
        }

        protected byte[] EncryptStringToBytes(byte[] key, string plainText)
        {
            if (plainText == null || plainText.Length <= 0)
            {
                throw new ArgumentNullException("plainText");
            }
            if (key == null || key.Length <= 0)
            {
                throw new ArgumentNullException("key");
            }

            byte[] encrypted;
            byte[] iv;

            using (var aes = CreateAes256Algorithm())
            {
                aes.Key = key;
                aes.GenerateIV();

                iv = aes.IV;

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            return CombineByteArrays(iv, encrypted);
        }

        protected string DecryptBytesToString(byte[] key, byte[] data)
        {
            if (key == null || key.Length <= 0)
            {
                throw new ArgumentNullException("key");
            }
            if (data == null || data.Length <= 0)
            {
                throw new ArgumentNullException("data");
            }

            var splitResult = SplitByteArray(data);
            byte[] iv = splitResult.Item1;
            byte[] cipherText = splitResult.Item2;
 
            string plaintext;

            using (var aes = CreateAes256Algorithm())
            {
                aes.Key = key;
                aes.IV = iv;

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (var msDecrypt = new MemoryStream(cipherText))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }

        #region Helper Methods
        private RijndaelManaged CreateAes256Algorithm()
        {
            return new RijndaelManaged { KeySize = 256, BlockSize = 128 };
        }

        private byte[] CombineByteArrays(byte[] first, byte[] second)
        {
            byte[] ret = new byte[first.Length + second.Length];
            Buffer.BlockCopy(first, 0, ret, 0, first.Length);
            Buffer.BlockCopy(second, 0, ret, first.Length, second.Length);
            return ret;
        }

        private Tuple<byte[], byte[]> SplitByteArray(byte[] data)
        {
            byte[] first = new byte[16];
            Buffer.BlockCopy(data, 0, first, 0, first.Length);
            byte[] second = new byte[data.Length - first.Length];
            Buffer.BlockCopy(data, first.Length, second, 0, second.Length);
            return Tuple.Create(first, second);
        }
        #endregion
    }
}
