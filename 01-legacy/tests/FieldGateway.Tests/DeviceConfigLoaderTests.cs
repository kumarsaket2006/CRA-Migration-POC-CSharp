using Indusoft.FieldGateway.Core.Config;
using Indusoft.FieldGateway.Core.Devices;
using NUnit.Framework;

namespace Indusoft.FieldGateway.Tests
{
    [TestFixture]
    public class DeviceConfigLoaderTests
    {
        [SetUp]
        public void Reset() { DeviceRegistry.Instance.Clear(); }

        [Test]
        public void LoadFromXml_RegistersDevicesAndTags()
        {
            const string xml = "<Gateway><Device id='PLC1' ip='127.0.0.1' port='1502' unit='1' poll='500'>" +
                               "<Tag name='Temp' address='100' input='true' scale='0.1' unit='degC'/></Device></Gateway>";
            int n = new DeviceConfigLoader().LoadFromXml(xml);
            Assert.AreEqual(1, n);
            FieldDevice d = DeviceRegistry.Instance.Find("PLC1");
            Assert.AreEqual(1502, d.Port);
            Assert.AreEqual(0.1, d.Tags[0].Scale, 1e-9);
        }
    }
}
