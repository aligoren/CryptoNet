using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CryptoNet
{
    public abstract class CryptoHelper :
        IBase64, ISHA256, IAes256, IAsymRsa, IXOR, IPBKDF2
    {
        Base64 b = new Base64();
        Sha256 sh26 = new Sha256();
        Aes256 aes256 = new Aes256();
        AsymRsa asymRsa = new AsymRsa();
        XOR xor = new XOR();
        PBKDF2 pbkdf2 = new PBKDF2();

        public string Base64Encode(string data)
        {
            
            return b.Base64Encode(data);
        }

        public string Base64Decode(string data)
        {
            return b.Base64Decode(data);
        }

        public string Sha256Encode(string data)
        {
            return sh26.Sha256Encode(data);
        }

        public byte[] Aes256KeyGenerate()
        {
            return aes256.Aes256GenerateKey();
        }

        public byte[] Aes256Encrypt(byte[] key, string plainText)
        {
            return aes256.Aes256EncryptStringToBytes(key, plainText);
        }

        public string Aes256Decrypt(byte[] key, byte[] data)
        {
            return aes256.Aes256DecryptBytesToString(key, data);
        }

        public string AsymRsaEncrypt(string text, int keySize, string publicKeyXml)
        {
            return asymRsa.AsymEnc(text, keySize, publicKeyXml);
        }

        public string AsymRsaDecrypt(string text, int keySize, string publicAndPrivateKeyXml)
        {
            return asymRsa.AsymDec(text, keySize, publicAndPrivateKeyXml);
        }

        public void AsymRsaGenerateKey(int keySize, out string publicKey, out string publicAndPrivateKey)
        {
            using (var provider = new RSACryptoServiceProvider(keySize))
            {
                publicKey = provider.ToXmlString(false);
                publicAndPrivateKey = provider.ToXmlString(true);
            }
        }

        public string XorEncrpyt(string input, string key)
        {
            return xor.XorEncrpyt(input, key);
        }

        public string XorDecrypt(string input, string key)
        {
            return xor.XorDecrypt(input, key);
        }

        public string GeneratePBKDF2Hash(string password)
        {
            return pbkdf2.GeneratePBKDF2Hash(password);
        }

        public bool ValidatePBKDF2Hash(string password, string correctHash)
        {
            return pbkdf2.ValidatePBKDF2Hash(password, correctHash);
        }
    }
}
