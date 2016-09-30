using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoNet
{
    public class Base64 : Base64Helper
    {

        protected internal string Base64Encode(string data)
        {
            byte[] dataSelect = Encoding.UTF8.GetBytes(data);
            string value = new string(Base64Encoding(dataSelect));
            return value;
        }

        protected internal string Base64Decode(string data)
        {
            byte[] dataSelect = Base64Decoding(data.ToCharArray());
            string value = Encoding.UTF8.GetString(dataSelect);
            return value;
        }

    }

    public interface IBase64
    {
        string Base64Encode(string data);
        string Base64Decode(string data);
    }
}
