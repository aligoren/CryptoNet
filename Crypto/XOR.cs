using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoNet
{
    public class XOR : XORHelper
    {
        protected internal string XorEncrpyt(string input, string key)
        {
            string rtnVal = Encrpyt(input, key);
            return rtnVal;
        }

        protected internal string XorDecrypt(string input, string key)
        {
            string rtnVal = Decrypt(input, key);
            return rtnVal;
        }
    }

    public interface IXOR
    {
        string XorEncrpyt(string input, string key);
        string XorDecrypt(string input, string key);
    }
}
