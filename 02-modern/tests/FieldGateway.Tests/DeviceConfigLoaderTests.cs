using Indusoft.FieldGateway.Core.Config;

namespace Indusoft.FieldGateway.Tests;

/// <summary>Regression tests for L02 (XXE) and L04 (secrets in config).</summary>
public class DeviceConfigLoaderTests
{
    private const string Valid =
        "<Gateway><Device id='PLC1' ip='127.0.0.1' port='1502' unit='1' poll='500'>" +
        "<Tag name='Temp' address='100' input='true' scale='0.1' unit='degC'/>" +
        "<Tag name='Setpoint' address='10' scale='0.1' writable='true' min='20' max='90'/></Device></Gateway>";

    [Fact]
    public void Load_ValidConfig_ParsesDevicesAndTags()
    {
        var devices = DeviceConfigLoader.LoadFromXml(Valid);
        var d = Assert.Single(devices);
        Assert.Equal(1502, d.Port);
        Assert.Equal(0.1, d.Tags[0].Scale, 9);
        Assert.True(d.FindTag("Setpoint")!.Writable);
    }

    [Fact]
    public void Load_ExternalEntity_Rejected()
    {
        const string xxe = "<?xml version='1.0'?><!DOCTYPE g [<!ENTITY x SYSTEM 'file:///etc/passwd'>]>" +
                           "<Gateway><Device id='&x;' ip='1.2.3.4'/></Gateway>";
        var ex = Assert.Throws<ConfigValidationException>(() => DeviceConfigLoader.LoadFromXml(xxe));
        Assert.Contains("XML rejected", ex.Errors[0]);
    }

    [Fact]
    public void Load_BillionLaughs_Rejected()
    {
        const string bomb = "<?xml version='1.0'?><!DOCTYPE l [<!ENTITY a 'aaaaaaaaaa'><!ENTITY b '&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;'>]>" +
                            "<Gateway><Device id='&b;' ip='x'/></Gateway>";
        Assert.Throws<ConfigValidationException>(() => DeviceConfigLoader.LoadFromXml(bomb));
    }

    [Fact]
    public void Load_PasswordAttribute_Rejected()
    {
        var ex = Assert.Throws<ConfigValidationException>(() =>
            DeviceConfigLoader.LoadFromXml("<Gateway><Device id='PLC1' ip='10.0.0.1' password='maint2012'/></Gateway>"));
        Assert.Contains(ex.Errors, e => e.Contains("secret store", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("<Gateway><Device id='PLC1' ip='10.0.0.1' port='70000'/></Gateway>")]
    [InlineData("<Gateway><Device id='PLC1' ip='10.0.0.1' unit='300'/></Gateway>")]
    [InlineData("<Gateway><Device id='../x' ip='10.0.0.1'/></Gateway>")]
    [InlineData("<Gateway><Device id='PLC1'/></Gateway>")]
    [InlineData("<Gateway><Device id='PLC1' ip='h'><Tag name='S' address='1' writable='true'/></Device></Gateway>")]
    public void Load_InvalidValues_Rejected(string xml) =>
        Assert.Throws<ConfigValidationException>(() => DeviceConfigLoader.LoadFromXml(xml));
}
