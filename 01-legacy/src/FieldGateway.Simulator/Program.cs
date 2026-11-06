using System;

namespace Indusoft.FieldGateway.Simulator
{
    internal static class Program
    {
        private static void Main(string[] args)
        {
            int port = args.Length > 0 ? int.Parse(args[0]) : 1502;
            ModbusSlaveSimulator sim = new ModbusSlaveSimulator(port);
            sim.Start();
            Console.WriteLine("Modbus TCP simulator listening on port {0}. Press ENTER to stop.", port);
            Console.ReadLine();
            sim.Stop();
        }
    }
}
