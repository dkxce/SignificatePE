using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.BC;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;
using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;

namespace dkxce
{

    // Based on https://github.com/Jemmy1228/TimeStampResponder-CSharp //

    public class TSResponder 
    {
        X509Certificate x509Cert;
        AsymmetricKeyParameter priKey;
        IX509Store x509Store;
        string hashAlg;
        public TSResponder(byte[] x509Cert, byte[] priKey, string hashAlg)
        {
            this.x509Cert = new X509CertificateParser().ReadCertificate(x509Cert);
            this.priKey = ((AsymmetricCipherKeyPair)(new PemReader(new StreamReader(new MemoryStream(priKey))).ReadObject())).Private;
            this.x509Store = X509StoreFactory.Create("Certificate/Collection", new X509CollectionStoreParameters(new X509CertificateParser().ReadCertificates(x509Cert)));
            this.hashAlg = hashAlg;
        }
        public byte[] GenResponse(byte[] bRequest, DateTime signTime, out bool isRFC, byte[] bSerial = null)
        {
            TimeStampRequest timeStampRequest = null;
            try { timeStampRequest = new TimeStampRequest(bRequest); int v = timeStampRequest.Version; } catch { timeStampRequest = null; }
            ;
            if (timeStampRequest == null)
            {
                isRFC = false;
                return Authenticode(bRequest, signTime);
            }
            else
            {
                isRFC = true;
                if (bSerial == null)
                {
                    bSerial = new byte[16];
                    new Random().NextBytes(bSerial);
                }
                BigInteger biSerial = new BigInteger(1, bSerial);
                return RFC3161(bRequest, signTime, biSerial);
            }
        }
        private byte[] RFC3161(byte[] bRequest, DateTime signTime, BigInteger biSerial)
        {
            TimeStampRequest timeStampRequest = new TimeStampRequest(bRequest);

            Asn1EncodableVector signedAttributes = new Asn1EncodableVector();
            signedAttributes.Add(new Attribute(CmsAttributes.ContentType, new DerSet(new DerObjectIdentifier("1.2.840.113549.1.7.1"))));
            signedAttributes.Add(new Attribute(CmsAttributes.SigningTime, new DerSet(new DerUtcTime(signTime))));
            AttributeTable signedAttributesTable = new AttributeTable(signedAttributes);
            signedAttributesTable.ToAsn1EncodableVector();

            TimeStampTokenGenerator timeStampTokenGenerator = new TimeStampTokenGenerator(priKey, x509Cert, new DefaultDigestAlgorithmIdentifierFinder().find(hashAlg).Algorithm.Id, "1.3.6.1.4.1.13762.3", signedAttributesTable, null);
            timeStampTokenGenerator.SetCertificates(x509Store);
            TimeStampResponseGenerator timeStampResponseGenerator = new TimeStampResponseGenerator(timeStampTokenGenerator, TspAlgorithms.Allowed);
            TimeStampResponse timeStampResponse = timeStampResponseGenerator.Generate(timeStampRequest, biSerial, signTime);
            byte[] result = timeStampResponse.GetEncoded();
            return result;
        }
        private byte[] Authenticode(byte[] bRequest, DateTime signTime)
        {
            string requestString = "";
            for (int i = 0; i < bRequest.Length; i++)
            {
                if (bRequest[i] >= 32)
                    requestString += (char)bRequest[i];
            }
            bRequest = Convert.FromBase64String(requestString);

            Asn1InputStream asn1InputStream = new Asn1InputStream(bRequest);
            Asn1Sequence instance = Asn1Sequence.GetInstance(asn1InputStream.ReadObject());
            Asn1Sequence instance2 = Asn1Sequence.GetInstance(instance[1]);
            Asn1TaggedObject instance3 = Asn1TaggedObject.GetInstance(instance2[1]);
            Asn1OctetString instance4 = Asn1OctetString.GetInstance(instance3.GetObject());
            byte[] octets = instance4.GetOctets();
            asn1InputStream.Close();

            Asn1EncodableVector signedAttributes = new Asn1EncodableVector();
            signedAttributes.Add(new Attribute(CmsAttributes.ContentType, new DerSet(new DerObjectIdentifier("1.2.840.113549.1.7.1"))));
            signedAttributes.Add(new Attribute(CmsAttributes.SigningTime, new DerSet(new DerUtcTime(signTime))));
            AttributeTable signedAttributesTable = new AttributeTable(signedAttributes);
            signedAttributesTable.ToAsn1EncodableVector();
            DefaultSignedAttributeTableGenerator signedAttributeGenerator = new DefaultSignedAttributeTableGenerator(signedAttributesTable);
            SignerInfoGeneratorBuilder signerInfoBuilder = new SignerInfoGeneratorBuilder();
            signerInfoBuilder.WithSignedAttributeGenerator(signedAttributeGenerator);
            ISignatureFactory signatureFactory = new Asn1SignatureFactory(hashAlg + "WithRSA", priKey);


            CmsSignedDataGenerator generator = new CmsSignedDataGenerator();
            generator.AddSignerInfoGenerator(signerInfoBuilder.Build(signatureFactory, x509Cert));
            generator.AddCertificates(x509Store);
            CmsSignedData cmsSignedData = generator.Generate(new CmsProcessableByteArray(octets), true);
            byte[] result = cmsSignedData.ContentInfo.GetEncoded("DER");
            return Encoding.ASCII.GetBytes(Convert.ToBase64String(result).ToArray());
        }
    }

    public class TSAServer
    {
        private TSResponder tsResponder;
        private HttpListener listener;
        private Thread listenThread;
        public static readonly string TSAPath = @"/TimeStamp/";
        public static readonly int TSAPort = 5453;

        public bool IsRunning { private set; get; } = false;

        public string Url => $"http://localhost:{TSAPort}" + TSAPath;

        public int Start(out Exception error)
        {
            error = null;
            try
            {
                string certPath = GetSPETemporaryDirectory();
                string cerFile = Path.Combine(IniSaved<int>.CurrentDirectory(), "TSA.cer");
                string keyFile = Path.Combine(IniSaved<int>.CurrentDirectory(), "TSA.key");
                if (!File.Exists(cerFile)) cerFile = certPath + "TSA.cer";
                if (!File.Exists(keyFile)) keyFile = certPath + "TSA.key";
                if (!File.Exists(cerFile)) File.WriteAllBytes(cerFile, global::SignificatePE.Properties.Resources.TSACER);
                if (!File.Exists(keyFile)) File.WriteAllBytes(keyFile, global::SignificatePE.Properties.Resources.TSAPRV);

                tsResponder = new TSResponder(File.ReadAllBytes(cerFile), File.ReadAllBytes(keyFile), "SHA1");
            }
            catch (Exception ex)
            {
                error = ex;
                MessageBox.Show($"Error creating TSA Server: {ex}");
                tsResponder = null;
                return 0;
            };

            try
            {
                listener = new HttpListener();
                listener.AuthenticationSchemes = AuthenticationSchemes.Anonymous;
                listener.Prefixes.Add($"http://localhost:{TSAPort}" + TSAPath);
                listener.Start();
            }
            catch (Exception ex)
            {
                error = ex;
                MessageBox.Show($"Error Launching TSA Server: {ex}");
                tsResponder = null;
                listener = null;
                return 0;
            };

            IsRunning = true;
            listenThread = new Thread(() =>
            {
                while (IsRunning)
                {
                    HttpListenerContext ctx = listener.GetContext();
                    ThreadPool.QueueUserWorkItem(new WaitCallback(TaskProc), ctx);
                };
            });
            listenThread.Start();
            return TSAPort;
        }

        public void Stop()
        {
            if (!IsRunning) return;
            tsResponder = null;
            listener.Stop();
            listener = null;
            IsRunning = false;
            listenThread.Abort();
            listenThread = null;
        }

        private void TaskProc(object o)
        {
            HttpListenerContext ctx = (HttpListenerContext)o;
            ctx.Response.StatusCode = 200;

            HttpListenerRequest request = ctx.Request;
            HttpListenerResponse response = ctx.Response;
            if (ctx.Request.HttpMethod != "POST")
            {
                StreamWriter writer = new StreamWriter(response.OutputStream, Encoding.ASCII);
                writer.WriteLine("SignificatePE TSA Server by dkxce (https://github.com/dkxce/SignificatePE)");
                writer.Close();
                ctx.Response.Close();
            }
            else
            {
                string log = "";
                string date = request.RawUrl.Remove(0, TSAPath.Length);
                DateTime signTime;
                if (!DateTime.TryParseExact(date, "yyyy-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out signTime))
                    signTime = DateTime.UtcNow;

                BinaryReader reader = new BinaryReader(request.InputStream);
                byte[] bRequest = reader.ReadBytes((int)request.ContentLength64);

                bool RFC;
                byte[] bResponse = tsResponder.GenResponse(bRequest, signTime, out RFC);
                if (RFC)
                {
                    response.ContentType = "application/timestamp-reply";
                    log += "RFC3161     \t";
                }
                else
                {
                    response.ContentType = "application/octet-stream";
                    log += "Authenticode\t";
                }
                log += signTime;
                BinaryWriter writer = new BinaryWriter(response.OutputStream);
                writer.Write(bResponse);
                writer.Close();
                ctx.Response.Close();
                Console.WriteLine(log);
            };
        }

        static TSAServer()
        {
            AppDomain.CurrentDomain.AssemblyResolve += TSAServer.CurrentDomain_AssemblyResolve;
        }

        public static void KillAll()
        {
            try { Directory.Delete(GetSPETemporaryDirectory(false), true); } catch { };
        }

        private static System.Reflection.Assembly CurrentDomain_AssemblyResolve(object sender, ResolveEventArgs args)
        {
            string assmPath = GetSPETemporaryDirectory();
            
            string assemblyNameString = (new AssemblyName(args.Name))?.Name;
            if (assemblyNameString == null) return null;

            if (assemblyNameString != "BouncyCastle.Crypto") return null;
            const string extension = ".dll";
            string fName = assmPath + assemblyNameString + extension;

            if (!File.Exists(fName))
                File.WriteAllBytes(fName, global::SignificatePE.Properties.Resources.BouncyCastle);

            Assembly assembly = Assembly.LoadFrom(fName);
            return assembly;
        }

        public static string GetSPETemporaryDirectory(bool create = true, string dirName = "SignificatePE")
        {
            string tempDirectory;
            if(string.IsNullOrEmpty(dirName))
                tempDirectory = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            else
                tempDirectory = Path.Combine(Path.GetTempPath(), dirName);

            try { Directory.CreateDirectory(tempDirectory); } catch { };
            tempDirectory = tempDirectory.TrimEnd('\\') + @"\";
            return tempDirectory;
        }
    }
}
