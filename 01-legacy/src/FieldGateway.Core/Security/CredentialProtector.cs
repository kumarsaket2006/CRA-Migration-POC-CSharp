using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Indusoft.FieldGateway.Core.Security
{
    /// <summary>"Encrypts" device passwords before they are written to the config file.</summary>
    public static class CredentialProtector
    {
        // LEGACY-ISSUE: L04 Hardcoded symmetric key and IV (CWE-321)
        private static readonly byte[] Key = Encoding.ASCII.GetBytes("FGkey123");
        private static readonly byte[] IV = Encoding.ASCII.GetBytes("FGiv4567");

        public static string Protect(string plain)
        {
            // LEGACY-ISSUE: L03 DES (56-bit) in CBC mode without authentication (CWE-327)
            using (DESCryptoServiceProvider des = new DESCryptoServiceProvider())
            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(Key, IV), CryptoStreamMode.Write))
                {
                    byte[] data = Encoding.UTF8.GetBytes(plain);
                    cs.Write(data, 0, data.Length);
                }
                return Convert.ToBase64String(ms.ToArray());
            }
        }

        public static string Unprotect(string cipher)
        {
            using (DESCryptoServiceProvider des = new DESCryptoServiceProvider())
            using (MemoryStream ms = new MemoryStream(Convert.FromBase64String(cipher)))
            using (CryptoStream cs = new CryptoStream(ms, des.CreateDecryptor(Key, IV), CryptoStreamMode.Read))
            using (StreamReader sr = new StreamReader(cs))
            {
                return sr.ReadToEnd();
            }
        }
    }
}
