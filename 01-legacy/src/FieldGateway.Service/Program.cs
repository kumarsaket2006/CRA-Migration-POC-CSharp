using System;
using System.ServiceProcess;

namespace Indusoft.FieldGateway.Service
{
    internal static class Program
    {
        private static void Main(string[] args)
        {
            if (Environment.UserInteractive || (args.Length > 0 && args[0] == "/console"))
            {
                GatewayService svc = new GatewayService();
                svc.StartInteractive(args);
                Console.WriteLine("FieldGateway running in console mode. Press ENTER to stop.");
                Console.ReadLine();
                svc.StopInteractive();
            }
            else
            {
                ServiceBase.Run(new ServiceBase[] { new GatewayService() });
            }
        }
    }
}
