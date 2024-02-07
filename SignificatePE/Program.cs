//
// C# 
// dkxce.Program
// http://github.com/dkxce/SignificatePE
// en,ru,1251,utf-8
//

// https://www.pkisolutions.com/accessing-and-using-certificate-private-keys-in-net-framework-net-core/

using System;
using System.IO;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using static dkxce.SignificatePE;
using SignificatePE;
using System.Diagnostics;
using System.Reflection;
using System.Windows.Forms;

namespace dkxce
{
    /*
     * Return Status Codes:
     * 0x00FFF - Signs or Files Count
     * 0x01000 - Help Mode
     * 0x02000 - Window Mode
     * 0x03000 - Verify Mode
     * 0x04000 - Remove Mode
     * 0x05000 - Overwrite Mode
     * 0x06000 - Append Mode
     * 0x07000 - Append Several Mode
     * 0x10000 - ERROR
     */
    internal class Program
    {

        #region DllImports

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        private const int SW_HIDE = 0;
        private const int SW_SHOW = 5;

        #endregion DllImports



        class ProxyDomain : MarshalByRefObject
{
    public Assembly GetAssembly(string assemblyPath)
    {
        try
        {
            return Assembly.LoadFrom(assemblyPath);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(ex.Message);
        }
    }
}

        [STAThread]
        static int Main(string[] args)
        {                       
            int result = 0x05000;
            string cert = null;
            string pass = null;
            string thmb = null;
            string hurl = null;
            int    wait = 250;
            bool help   = false;
            bool verify = false;
            bool remove = false;
            bool silent = false;
            SignificateMode ovw_mode = SignificateMode.Overwrite;
            List<string> files = new List<string>();
            List<uint> Algos = new List<uint>();

            if (args != null && args.Length > 0)
                foreach (string arg in args)
                {
                    if (arg.Contains("?")) { help = true; break; };
                    if ((arg.StartsWith("/c=") || arg.StartsWith("-c=")) && arg.Length > 3)
                        cert = arg.Substring(3);
                    if ((arg.StartsWith("/p=") || arg.StartsWith("-p=")) && arg.Length > 3)
                        pass = arg.Substring(3);
                    if ((arg.StartsWith("/t=") || arg.StartsWith("-t=")) && arg.Length > 3)
                        thmb = arg.Substring(3);
                    if ((arg.StartsWith("/h=") || arg.StartsWith("-h=")) && arg.Length > 3)
                        hurl = arg.Substring(3);
                    if ((arg.StartsWith("/a=") || arg.StartsWith("-a=") || arg.StartsWith("/A=") || arg.StartsWith("-A=")) && arg.Length > 3)
                    {
                        string algs = arg.Substring(3).ToLower();
                        if(algs.Contains("sha") && !Algos.Contains(SignificatePE.CALG_SHA)) Algos.Add(SignificatePE.CALG_SHA);
                        if(algs.Contains("s256") && !Algos.Contains(SignificatePE.CALG_SHA_256)) Algos.Add(SignificatePE.CALG_SHA_256);
                        if(algs.Contains("s512") && !Algos.Contains(SignificatePE.CALG_SHA_512)) Algos.Add(SignificatePE.CALG_SHA_512);
                    };                        
                    if ((arg.StartsWith("/w=") || arg.StartsWith("-w=")) && arg.Length > 3 && ushort.TryParse(arg.Substring(3), out ushort to))
                        wait = to;
                    if (arg.StartsWith("/v") || arg.StartsWith("-v"))
                    { verify = true; result = 0x03000; };
                    if (arg.StartsWith("/r") || arg.StartsWith("-r") || arg.StartsWith("/d") || arg.StartsWith("-d"))
                    { remove = true; result = 0x04000; };
                    if (arg.StartsWith("/s") || arg.StartsWith("-s"))
                        silent = true;
                    if (arg.StartsWith("/n") || arg.StartsWith("-n"))
                    { ovw_mode = SignificateMode.Append; result = 0x06000; };
                    if (arg.StartsWith("/m") || arg.StartsWith("-m"))
                    { ovw_mode = SignificateMode.SeveralNew; result = 0x07000; };
                    if (arg.StartsWith("/") || arg.StartsWith("-")) continue;
                    if (arg.StartsWith("@") && arg.Length > 1)
                    {
                        string fn = arg.Substring(1);
                        try { if (!File.Exists(fn)) continue; } catch { continue; };
                        foreach(string f in File.ReadAllLines(fn))
                            try { if (File.Exists(f)) files.Add(f); } catch { };
                        continue;
                    };
                    if(arg == "*")
                    {
                        files.AddRange(Directory.GetFiles(AppDomain.CurrentDomain.BaseDirectory, "*.exe", SearchOption.TopDirectoryOnly));
                        files.AddRange(Directory.GetFiles(AppDomain.CurrentDomain.BaseDirectory, "*.dll", SearchOption.TopDirectoryOnly));
                        files.AddRange(Directory.GetFiles(AppDomain.CurrentDomain.BaseDirectory, "*.msi", SearchOption.TopDirectoryOnly));                        
                    };                    
                    try { if (File.Exists(arg)) files.Add(arg); } catch { };
                };

            /* HEADER */
            Console.WriteLine("***************************************************************");
            Console.WriteLine("********            dkxce PE Significator           ***********");
            Console.WriteLine("********             v 2024-02-07 ST TSA            ***********");
            Console.WriteLine("********    http://github.com/dkxce/SignificatePE   ***********");
            Console.WriteLine("***************************************************************");
            Console.WriteLine("*****                                                     *****");
            Console.WriteLine("***** Usage:                                              *****");
            Console.WriteLine("*****       > SignificatePE.exe [flags] <file> [file]     *****");
            Console.WriteLine("***** Flags:                                              *****");
            Console.WriteLine("*****       /c=<file>   - Specify Certificate File (pfx)  *****");
            Console.WriteLine("*****       /p=<pass>   - Specify Certificate Password    *****");
            Console.WriteLine("*****       /t=<thmb>   - Set Certificate by Thumbprint   *****");
            Console.WriteLine("*****       /h=<url>    - Set Custom TimeStamp Server     *****");
            Console.WriteLine("*****       /a=<alg>    - Set Hash Alg (sha, s256, s512)  *****");            
            Console.WriteLine("*****       /w=<sec>    - Wait Timeout In ms              *****");            
            Console.WriteLine("*****       /r or /d    - Remove Signatures (DeSign)      *****");
            Console.WriteLine("*****       /n          - Append New Mode (multisign)     *****");
            Console.WriteLine("*****       /m          - Append Several New (batch)      *****");
            Console.WriteLine("*****       /v          - Verify Only (No Sign)           *****");
            Console.WriteLine("*****       /s          - Silent Mode (No Questions)      *****");
            Console.WriteLine("*****                                                     *****");
            Console.WriteLine("***************************************************************");
            Console.WriteLine("***************************************************************");
            Console.WriteLine("***************************************************************");            
            if (help) { Thread.Sleep(wait == 0 ? 0 : 3500); return result += 0x1000; };
            Console.WriteLine();

            /* WINDOW MODE */
            if (args == null || args.Length == 0)
            {
                Console.WriteLine("No arguments passed, starting Window Mode ...");
                System.Windows.Forms.Application.EnableVisualStyles();
                System.Windows.Forms.Application.SetCompatibleTextRenderingDefault(false);
                SignForm signForm = new SignForm();
                IntPtr cHandle = GetConsoleWindow();
                if(cHandle != IntPtr.Zero) (new Thread(new ThreadStart(() => { Thread.Sleep(1000); ShowWindow(cHandle, SW_HIDE); }))).Start();
                System.Windows.Forms.Application.Run(signForm);
                return result += 0x2000;
            };

            /* CHECKS */            
            if (string.IsNullOrEmpty(cert) && string.IsNullOrEmpty(thmb) && !verify && !remove) { Console.WriteLine("Certificate or Thumbprint not set"); System.Threading.Thread.Sleep(3500); return result += 0x10001; };
            if (files.Count == 0) { Console.WriteLine("File(s) not set"); System.Threading.Thread.Sleep(3500); return result += 0x10002; };

            /* PROCESS */
            try
            {
                if (verify)
                {
                    foreach (string f in files)
                    {
                        FileInfo fi = new FileInfo(f);
                        Console.WriteLine($" VERIFY FILE: ");
                        Console.WriteLine($" {{ ");
                        Console.WriteLine($"   Name: {fi.Name}");
                        Console.WriteLine($"   Path: {fi.FullName}");
                        Verify(fi.FullName);
                        Console.WriteLine($" }} ");
                        result++;
                        System.Threading.Thread.Sleep(wait);
                    };
                }
                else if (remove)
                {
                    foreach (string f in files)
                    {
                        FileInfo fi = new FileInfo(f);
                        if (fi.Name == "SignificatePE.exe") continue;
                        Console.WriteLine($" DESIGN FILE: ");
                        Console.WriteLine($" {{ ");
                        Console.WriteLine($"   Name: {fi.Name}");
                        Console.WriteLine($"   Path: {fi.FullName}");
                        string rStatus = VertificatePE.RemoveCertificateFileInfo(fi.FullName, out Exception ex) ? "Signature Removed" : $"Remove Signature Failed";
                        Console.WriteLine($"   Status: {rStatus}");
                        if(ex != null) Console.WriteLine($"   Error: {ex.Message}");
                        Verify(fi.FullName);
                        Console.WriteLine($" }} ");
                        result++;
                        System.Threading.Thread.Sleep(wait);
                    };
                }
                else
                {
                    bool passwAsked = false;
                    if (!string.IsNullOrEmpty(cert))
                    {
                        FileInfo ci = new FileInfo(cert);                        
                        Console.WriteLine($" CERTIFICATE:");
                        Console.WriteLine($" {{ ");
                        Console.WriteLine($"   Name: {ci.Name}");
                        Console.WriteLine($"   Path: {ci.FullName}");
                        Console.WriteLine($"   Pass: {pass}");
                        Console.WriteLine($" }} ");                        

                        if (Algos.Count == 0) Algos.Add(0x0000800c);
                        foreach (string f in files)
                        {
                            FileInfo fi = new FileInfo(f);
                            if (fi.Name == "SignificatePE.exe") break;
                            Console.WriteLine($" PROCESS FILE: ");
                            Console.WriteLine($" {{ ");
                            Console.WriteLine($"   Name: {fi.Name}");
                            Console.WriteLine($"   Path: {fi.FullName}");

                            if (ovw_mode == SignificateMode.SeveralNew)
                                VertificatePE.RemoveCertificateFileInfo(fi.FullName, out Exception ex);

                            foreach (uint algo in Algos)
                            {
                                while (true)
                                {
                                    Console.WriteLine($"   Algo: {GetFriendlyAlgoName(algo)} ({GetFriendlyAlgoID(algo)})");
                                    bool res = string.IsNullOrEmpty(thmb) ? SignificatePE.SignWithCertFile(fi.FullName, cert, pass, hurl, algo, ovw_mode == SignificateMode.Append || ovw_mode == SignificateMode.SeveralNew) : SignificatePE.SignWithThumbprint(fi.FullName, thmb, hurl, algo, ovw_mode == SignificateMode.Append || ovw_mode == SignificateMode.SeveralNew);
                                    Console.WriteLine($"     Status: {res}");
                                    Exception ex = SignificatePE.GetLastError();
                                    if (ex == null) ex = new System.ComponentModel.Win32Exception(0);
                                    Console.WriteLine($"     Info: {ex.Message}");                                    
                                    if (!passwAsked && !silent && ex.Message.Contains("-2147024810"))
                                    {
                                        Console.Write("  Enter valid password: ");
                                        string passwl = Console.ReadLine().Trim();
                                        pass = passwl;
                                        passwAsked = true;
                                        continue;
                                    };
                                    break;
                                };
                                result++;
                                System.Threading.Thread.Sleep(wait);
                            };
                            Verify(fi.FullName);
                            Console.WriteLine($" }} ");
                        };
                    };

                    if (!string.IsNullOrEmpty(thmb))
                    {
                        Console.WriteLine($" THUMBPRINT: {thmb}");
                        if (Algos.Count == 0) Algos.Add(0x0000800c);
                        foreach (string f in files)
                        {
                            FileInfo fi = new FileInfo(f);
                            if (fi.Name == "SignificatePE.exe") continue;
                            Console.WriteLine($" SING FILE: ");
                            Console.WriteLine($" {{ ");
                            Console.WriteLine($"   Name: {fi.Name}");
                            Console.WriteLine($"   Path: {fi.FullName}");

                            if (ovw_mode == SignificateMode.SeveralNew)
                                VertificatePE.RemoveCertificateFileInfo(fi.FullName, out Exception ex);

                            foreach (uint algo in Algos)
                            {
                                Console.WriteLine($"   Algo: {GetFriendlyAlgoName(algo)} ({GetFriendlyAlgoID(algo)})");
                                bool res = SignificatePE.SignWithThumbprint(fi.FullName, thmb, hurl, algo, ovw_mode == SignificateMode.Append || ovw_mode == SignificateMode.SeveralNew);
                                Console.WriteLine($"     Status: {res}");
                                Exception ex = SignificatePE.GetLastError();
                                if (ex == null) ex = new System.ComponentModel.Win32Exception(0);
                                Console.WriteLine($"     Info: {ex.Message}");
                                result++;
                                System.Threading.Thread.Sleep(wait);
                            };
                            Verify(fi.FullName);
                            Console.WriteLine($" }} ");
                        };
                    };
                };

            }
            catch (Exception ex) { Console.WriteLine($"   Error: {ex}"); Console.WriteLine($" }} ");  };
            Console.WriteLine();

            Console.WriteLine("***************************************************************");
            Console.WriteLine($"**************************RESULT:{result:X6}************************");
            Console.WriteLine("***************************************************************");

            System.Threading.Thread.Sleep(wait);
            return result;
        }        

        private static void Verify(string fileName)
        {
            try
            {
                VertificatePE.CHECK_RESULT chr = VertificatePE.CheckFileCertificate(fileName, out Exception err);
                Console.WriteLine($"   Sign: {chr.Status}");
                if (chr.Signatures == null || chr.Signatures.Length == 0) Console.WriteLine($"   Signatures: 0");
                else
                {
                    Console.WriteLine($"   Signatures: {chr.Signatures.Length}");
                    foreach (VertificatePE.VERIFY_SIGNATURE ver in chr.Signatures)
                    {
                        Console.WriteLine($"   {{");
                        Console.WriteLine($"       {"Signed",10}: {ver.Signed} UTC");
                        Console.WriteLine($"       {"Issuer",10}: {ver.Issuer}");
                        Console.WriteLine($"       {"Subject",10}: {ver.Certificate?.Subject}");
                        Console.WriteLine($"       {"Serial",10}: {ver.Certificate?.SerialNumber}");
                        Console.WriteLine($"       {"Thumbprint",10}: {ver.Certificate?.Thumbprint}");
                        Console.WriteLine($"       {"Hash/Enc",10}: {ver.HashAlgorithm?.FriendlyName}/{ver.HashEncryptionAlgorithm?.FriendlyName}");
                        Console.WriteLine($"       {"Valid Till",10}: {ver.Certificate?.NotAfter}");
                        Console.WriteLine($"   }}");
                    };
                };
            }
            catch { };
        }        
    }
}

/* OLD -- BAD */

///// <summary>
/////     __declspec(dllexport) HRESULT __cdecl Significate(_In_ DWORD signingCertContext, _In_ LPCWSTR packageFilePath)
/////     The equivalent of LPCSTR is string or StringBuilder
///// </summary>
///// <param name="certContext"></param>
///// <param name="fileName"></param>
///// <returns></returns>
//[DllImport("Significator.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
//private extern static long Significate(IntPtr certContext /* X5092Cert.Handle */, string fileName);

/* 
X509Certificate2 cert = new X509Certificate2(@"C:\DISK2\PROJECTS\Development\OAE_CSharp\MSolDrvUpd\MSolDesk\bin\Install\SIGN_CERT.pfx", "msdoom");

RSACryptoServiceProvider rsacsp = (RSACryptoServiceProvider)cert.PrivateKey;
CspParameters cspParam = new CspParameters();
cspParam.KeyContainerName = rsacsp.CspKeyContainerInfo.KeyContainerName;
cspParam.KeyNumber = rsacsp.CspKeyContainerInfo.KeyNumber == KeyNumber.Exchange ? 1 : 2;
RSACryptoServiceProvider aescsp = new RSACryptoServiceProvider(cspParam);
aescsp.PersistKeyInCsp = false;

long res = Significate(cert.Handle, @"C:\Downloads\Runner.exe");
*/