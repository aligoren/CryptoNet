using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoNet
{
    public class Aes256 : Aes256Helper
    {
        protected internal byte[] Aes256GenerateKey()
        {
            return GenerateKey();
        }

        protected internal byte[] Aes256EncryptStringToBytes(byte[] key, string plainText)
        {
            return EncryptStringToBytes(key, plainText);
        }

        protected internal string Aes256DecryptBytesToString(byte[] key, byte[] data)
        {
            return DecryptBytesToString(key, data);
        }
    }

    public interface IAes256
    {
        byte[] Aes256KeyGenerate();
        byte[] Aes256Encrypt(byte[] key, string plainText);
        string Aes256Decrypt(byte[] key, byte[] data);
    }
}
