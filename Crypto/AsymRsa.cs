using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoNet
{
    class AsymRsa : AsymRsaHelper
    {
        protected internal string AsymEnc(string text, int keySize, string publicKeyXml)
        {
            return EncryptText(text, keySize, publicKeyXml);
        }

        protected internal string AsymDec(string text, int keySize, string publicAndPrivateKeyXml)
        {
            return DecryptText(text, keySize, publicAndPrivateKeyXml);
        }
    }

    public interface IAsymRsa
    {
        void AsymRsaGenerateKey(int keySize, out string publicKey, out string publicAndPrivateKey);
        string AsymRsaEncrypt(string text, int keySize, string publicKeyXml);
        string AsymRsaDecrypt(string text, int keySize, string publicAndPrivateKeyXml);
    }
}
