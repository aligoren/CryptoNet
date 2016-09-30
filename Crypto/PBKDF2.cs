using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoNet
{
    public class PBKDF2 : PBKDF2Helper
    {
        protected internal string GeneratePBKDF2Hash(string password)
        {
            return HashPassword(password);
        }

        protected internal bool ValidatePBKDF2Hash(string password, string correctHash)
        {
            return ValidatePassword(password, correctHash);
        }
    }

    public interface IPBKDF2
    {
        string GeneratePBKDF2Hash(string password);
        bool ValidatePBKDF2Hash(string password, string correctHash);
    }
}
