using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoNet
{
    public class XORHelper
    {
        protected static string Encrpyt(string input, string key)
        {
            var result = new StringBuilder();

            for (int c = 0; c < input.Length; c++)
                result.Append((char)((uint)input[c] ^ (uint)key[c % key.Length]));

            return result.ToString();
        }

        protected static string Decrypt(string input, string key)
        {
            var result = new StringBuilder();

            for (int c = 0; c < input.Length; c++)
                result.Append((char)((uint)input[c] ^ (uint)key[c % key.Length]));

            return result.ToString();
        }
    }
}
