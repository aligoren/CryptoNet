using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoNet
{
    public class Sha256 : Sha256Helper
    {
        protected internal string Sha256Encode(string data)
        {
            return SHA256Encoding(data);
        }

        
    }

    public interface ISHA256
    {
        string Sha256Encode(string data);
    }
}
