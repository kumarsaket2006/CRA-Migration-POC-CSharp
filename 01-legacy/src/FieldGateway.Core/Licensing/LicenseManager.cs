using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

namespace Indusoft.FieldGateway.Core.Licensing
{
    public class LicenseManager
    {
        // LEGACY-ISSUE: L04 Hardcoded secret used to validate license keys (CWE-798)
        private const string LicenseSecret = "Indus0ft-FG-2012-$ecret!";

        public bool IsLicensed()
        {
            // LEGACY-ISSUE: L12 Windows-only API (registry) in core library
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Indusoft\FieldGateway"))
            {
                if (key == null) return false;
                string customer = (string)key.GetValue("Customer");
                string licenseKey = (string)key.GetValue("LicenseKey");
                if (customer == null || licenseKey == null) return false;
                return licenseKey == ComputeKey(customer);
            }
        }

        public static string ComputeKey(string customer)
        {
            // LEGACY-ISSUE: L03 SHA1 with string-concatenated secret (weak, length-extension prone) (CWE-328)
            using (SHA1 sha = SHA1.Create())
            {
                byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(LicenseSecret + customer));
                return Convert.ToBase64String(hash).Substring(0, 20);
            }
        }
    }
}
