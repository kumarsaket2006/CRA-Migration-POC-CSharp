using System;
using System.Globalization;
using System.IO;
using System.Xml;
using Indusoft.FieldGateway.Core.Devices;
using log4net;

namespace Indusoft.FieldGateway.Core.Config
{
    /// <summary>
    /// Loads device configuration from XML, e.g.
    /// &lt;Gateway&gt;&lt;Device id="PLC1" ip="10.0.0.5" port="502" unit="1" poll="500" password="..."&gt;
    ///   &lt;Tag name="Temp" address="100" length="1" scale="0.1" unit="degC" writable="false"/&gt;
    /// </summary>
    public class DeviceConfigLoader
    {
        private static readonly ILog Log = LogManager.GetLogger(typeof(DeviceConfigLoader));

        public int LoadFromFile(string path)
        {
            return LoadFromXml(File.ReadAllText(path));
        }

        public int LoadFromXml(string xml)
        {
            // LEGACY-ISSUE: L02 XmlDocument with default resolver; on .NET 4.0 DTD processing and external
            // entities are enabled -> XXE / file disclosure / billion-laughs DoS (CWE-611, CWE-776)
            XmlDocument doc = new XmlDocument();
            doc.XmlResolver = new XmlUrlResolver();
            doc.LoadXml(xml);

            int count = 0;
            foreach (XmlNode node in doc.SelectNodes("/Gateway/Device"))
            {
                FieldDevice device = new FieldDevice();
                device.Id = Attr(node, "id");
                device.Name = Attr(node, "name") ?? device.Id;
                device.IpAddress = Attr(node, "ip");
                device.Port = int.Parse(Attr(node, "port") ?? "502");
                device.UnitId = byte.Parse(Attr(node, "unit") ?? "1");
                device.PollIntervalMs = int.Parse(Attr(node, "poll") ?? "1000");
                device.MaintenancePassword = Attr(node, "password");

                foreach (XmlNode t in node.SelectNodes("Tag"))
                {
                    TagDefinition tag = new TagDefinition();
                    tag.Name = Attr(t, "name");
                    tag.Address = ushort.Parse(Attr(t, "address"));
                    tag.Length = ushort.Parse(Attr(t, "length") ?? "1");
                    tag.Scale = double.Parse(Attr(t, "scale") ?? "1", CultureInfo.InvariantCulture);
                    tag.Unit = Attr(t, "unit");
                    tag.IsInput = "true".Equals(Attr(t, "input"), StringComparison.OrdinalIgnoreCase);
                    tag.Writable = "true".Equals(Attr(t, "writable"), StringComparison.OrdinalIgnoreCase);
                    device.Tags.Add(tag);
                }

                // LEGACY-ISSUE: L08 Credentials written to log
                Log.Debug(string.Format("Loaded device {0} at {1} (maintenance pwd={2})", device.Id, device.IpAddress, device.MaintenancePassword));
                DeviceRegistry.Instance.Register(device);
                count++;
            }
            return count;
        }

        private static string Attr(XmlNode node, string name)
        {
            XmlAttribute a = node.Attributes[name];
            return a == null ? null : a.Value;
        }
    }
}
