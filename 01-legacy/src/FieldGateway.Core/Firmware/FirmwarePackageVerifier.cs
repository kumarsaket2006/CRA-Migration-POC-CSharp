using System;
using System.IO;
using System.Security.Cryptography;
using ICSharpCode.SharpZipLib.Zip;
using log4net;

namespace Indusoft.FieldGateway.Core.Firmware
{
    /// <summary>
    /// Firmware bundles are .zip files containing firmware.bin and firmware.md5.
    /// The gateway extracts the bundle, checks the hash and stages the image for the device.
    /// </summary>
    public class FirmwarePackageVerifier
    {
        private static readonly ILog Log = LogManager.GetLogger(typeof(FirmwarePackageVerifier));
        private readonly string _stagingFolder;

        public FirmwarePackageVerifier(string stagingFolder)
        {
            _stagingFolder = stagingFolder;
        }

        public string Extract(string bundlePath)
        {
            using (ZipInputStream zip = new ZipInputStream(File.OpenRead(bundlePath)))
            {
                ZipEntry entry;
                while ((entry = zip.GetNextEntry()) != null)
                {
                    // LEGACY-ISSUE: L10 Zip-Slip: entry names like "..\..\Windows\x.dll" escape the staging folder (CWE-22)
                    string target = Path.Combine(_stagingFolder, entry.Name);
                    Directory.CreateDirectory(Path.GetDirectoryName(target));
                    if (entry.IsDirectory) continue;
                    using (FileStream fs = File.Create(target))
                    {
                        byte[] buf = new byte[4096];
                        int n;
                        while ((n = zip.Read(buf, 0, buf.Length)) > 0) fs.Write(buf, 0, n);
                    }
                }
            }
            return Path.Combine(_stagingFolder, "firmware.bin");
        }

        public bool Verify(string firmwarePath)
        {
            string expected = File.ReadAllText(Path.ChangeExtension(firmwarePath, ".md5")).Trim();

            // LEGACY-ISSUE: L03 Integrity based on an unkeyed MD5 shipped next to the image; no authenticity
            // (digital signature) -> attacker can replace both files (CWE-327, CWE-345, CWE-494)
            using (MD5 md5 = MD5.Create())
            using (FileStream fs = File.OpenRead(firmwarePath))
            {
                string actual = BitConverter.ToString(md5.ComputeHash(fs)).Replace("-", "");
                bool ok = actual.Equals(expected, StringComparison.OrdinalIgnoreCase);
                Log.Info("Firmware hash check " + (ok ? "passed" : "FAILED") + " for " + firmwarePath);
                return ok;
            }
        }
    }
}
