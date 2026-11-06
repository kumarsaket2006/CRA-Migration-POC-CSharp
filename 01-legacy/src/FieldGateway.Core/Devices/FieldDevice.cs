using System;
using System.Collections.Generic;

namespace Indusoft.FieldGateway.Core.Devices
{
    [Serializable]
    public class FieldDevice
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string IpAddress { get; set; }
        public int Port { get; set; }
        public byte UnitId { get; set; }
        public int PollIntervalMs { get; set; }

        // LEGACY-ISSUE: L04 Device maintenance password kept in clear text in memory and config
        public string MaintenancePassword { get; set; }

        public List<TagDefinition> Tags { get; set; }

        public FieldDevice()
        {
            Port = 502;
            UnitId = 1;
            PollIntervalMs = 1000;
            Tags = new List<TagDefinition>();
        }
    }

    [Serializable]
    public class TagDefinition
    {
        public string Name { get; set; }
        public ushort Address { get; set; }
        public ushort Length { get; set; }
        public bool IsInput { get; set; }
        public bool Writable { get; set; }
        public double Scale { get; set; }
        public string Unit { get; set; }
    }

    [Serializable]
    public class TagValue
    {
        public string DeviceId { get; set; }
        public string TagName { get; set; }
        public double Value { get; set; }
        public DateTime TimestampUtc { get; set; }
        public string Quality { get; set; }
    }

    public class TagValueChangedEventArgs : EventArgs
    {
        public TagValue Value { get; private set; }
        public TagValueChangedEventArgs(TagValue value) { Value = value; }
    }
}
