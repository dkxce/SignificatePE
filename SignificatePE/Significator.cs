//
// C# 
// dkxce.SignificatePE
// http://github.com/dkxce/SignificatePE
// en,ru,1251,utf-8
//

using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace dkxce
{
    public static class SignificatePE
    {
        public enum SignificateMode
        {
            Overwrite = 0,
            Append = 1
        }

        #region TIME SERVERS

        private const string TIME_SERVER_A = "http://timestamp.digicert.com";
        private const string TIME_SERVER_B = "http://timestamp.comodoca.com";
        private const string TIME_SERVER_C = "http://timestamp.sectigo.com";

        #endregion TIME SERVERS

        #region CONSTS

        #region algidHash

        private const int OK_RESULT = 0;

        public const uint CALG_NO_SIGN = 0x00002000;
        public const uint CALG_MD5 = 0x00008003; // hash
        public const uint CALG_SHA = 0x00008004; // sign
        public const uint CALG_SHA1 = 0x00008004; // sign
        public const uint CALG_SHA_256 = 0x0000800c; // sign
        public const uint CALG_SHA_512 = 0x0000800e; // sign
        public const uint CALG_RSA = 0x00002400; // keysign
        public const uint CALG_DSA = 0x00002200; // keysign
        public const uint CALG_ECC = 0x00002203; // keysign

        private const string CALN_NO_SIGN = "nosign";
        private const string CALN_MD5 = "md5"; // hash
        private const string CALN_SHA = "sha1"; // sign
        private const string CALN_SHA1 = "sha1"; // sign
        private const string CALN_SHA_256 = "sha256"; // sign
        private const string CALN_SHA_512 = "sha512"; // sign
        private const string CALN_RSA = "rsa"; // keysign
        private const string CALN_DSA = "dsa"; // keysign
        private const string CALN_ECC = "ecdsa"; // keysign

        private const string CALO_MD5 = "1.2.840.113549.2.5"; // hash
        private const string CALO_SHA = "1.3.14.3.2.26"; // sign
        private const string CALO_SHA1 = "1.3.14.3.2.26"; // sign
        private const string CALO_SHA_256 = "2.16.840.1.101.3.4.2.1"; // sign
        private const string CALO_SHA_512 = "2.16.840.1.101.3.4.2.3"; // sign
        private const string CALO_RSA = "1.2.840.113549.1.1.1"; // keysign
        private const string CALO_DSA = "1.2.840.10040.4.1"; // keysign
        private const string CALO_ECC = "1.2.840.10045.2.1"; // keysign

        #endregion algidHash

        #region dwAttrChoice

        private static readonly uint SIGNER_NO_ATTR = 0x00000000;
        private static readonly uint SIGNER_AUTHCODE_ATTR = 0x00000001;

        #endregion dwAttrChoice

        #region dwCertPolicy

        private static readonly uint SIGNER_CERT_POLICY_STORE = 0x00000001;
        private static readonly uint SIGNER_CERT_POLICY_CHAIN = 0x00000002;
        private static readonly uint SIGNER_CERT_POLICY_CHAIN_NO_ROOT = 0x00000008;

        #endregion dwCertPolicy

        #region dwCertEncodingType

        private static readonly int X509_ASN_ENCODING = 0x00000001;
        private static readonly int PKCS_7_ASN_ENCODING = 0x00010000;

        #endregion dwCertEncodingType

        #region dwCertChoice

        private static readonly uint SIGNER_CERT_SPC_FILE = 0x01;
        private static readonly uint SIGNER_CERT_STORE = 0x02;
        private static readonly uint SIGNER_CERT_SPC_CHAIN = 0x03;

        #endregion dwCertChoice

        #region dwSubjectChoice
        private static readonly uint SIGNER_SUBJECT_FILE = 0x01;
        private static readonly uint SIGNER_SUBJECT_BLOB = 0x02;
        #endregion dwSubjectChoice

        private static readonly int SIGNER_TIMESTAMP_RFC3161 = 0x0002;
        private static readonly int CERT_STORE_PROV_MEMORY = 0x0002;
        private static readonly uint PVK_TYPE_KEYCONTAINER = 0x0002;
        private static readonly int CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES = 0x0005;
        private static readonly int CERT_STORE_CREATE_NEW_FLAG = 0x00002000;

        #endregion CONSTS

        #region Structures

        [StructLayoutAttribute(LayoutKind.Sequential)]
        private struct SIGNER_SUBJECT_INFO
        {
            public uint cbSize;
            public IntPtr pdwIndex;
            public uint dwSubjectChoice;
            public SubjectChoiceUnion Union1;
            [StructLayoutAttribute(LayoutKind.Explicit)]
            internal struct SubjectChoiceUnion
            {
                [FieldOffsetAttribute(0)]
                public System.IntPtr pSignerFileInfo;
                [FieldOffsetAttribute(0)]
                public System.IntPtr pSignerBlobInfo;
            };
        }

        [StructLayoutAttribute(LayoutKind.Sequential)]
        private struct SIGNER_CERT
        {
            public uint cbSize;
            public uint dwCertChoice;
            public SignerCertUnion Union1;
            [StructLayoutAttribute(LayoutKind.Explicit)]
            internal struct SignerCertUnion
            {
                [FieldOffsetAttribute(0)]
                public IntPtr pwszSpcFile;
                [FieldOffsetAttribute(0)]
                public IntPtr pCertStoreInfo;
                [FieldOffsetAttribute(0)]
                public IntPtr pSpcChainInfo;
            };
            public IntPtr hwnd;
        }

        [StructLayoutAttribute(LayoutKind.Sequential)]
        private struct SIGNER_SIGNATURE_INFO
        {
            public uint cbSize;
            public uint algidHash; // ALG_ID
            public uint dwAttrChoice;
            public IntPtr pAttrAuthCode;
            public IntPtr psAuthenticated; // PCRYPT_ATTRIBUTES
            public IntPtr psUnauthenticated; // PCRYPT_ATTRIBUTES
        }

        [StructLayoutAttribute(LayoutKind.Sequential)]
        private struct SIGNER_FILE_INFO
        {
            public uint cbSize;
            public IntPtr pwszFileName;
            public IntPtr hFile;
        }

        [StructLayoutAttribute(LayoutKind.Sequential)]
        private struct SIGNER_CERT_STORE_INFO
        {
            public uint cbSize;
            public IntPtr pSigningCert; // CERT_CONTEXT
            public uint dwCertPolicy;
            public IntPtr hCertStore;
        }

        [StructLayoutAttribute(LayoutKind.Sequential)]
        private struct SIGNER_CONTEXT
        {
            public uint cbSize;
            public uint cbBlob;
            public IntPtr pbBlob;
        }

        [StructLayoutAttribute(LayoutKind.Sequential)]
        private struct SIGNER_PROVIDER_INFO
        {
            public uint cbSize;
            public IntPtr pwszProviderName;
            public uint dwProviderType;
            public uint dwKeySpec;
            public uint dwPvkChoice;
            public SignerProviderUnion Union1;
            [StructLayoutAttribute(LayoutKind.Explicit)]
            internal struct SignerProviderUnion
            {
                [FieldOffsetAttribute(0)]
                public IntPtr pwszPvkFileName;
                [FieldOffsetAttribute(0)]
                public IntPtr pwszKeyContainer;
            };
        }

        #endregion Structures

        #region Imports

        [DllImport("Mssign32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int SignerSign(
            IntPtr pSubjectInfo,        // SIGNER_SUBJECT_INFO
            IntPtr pSignerCert,         // SIGNER_CERT
            IntPtr pSignatureInfo,      // SIGNER_SIGNATURE_INFO
            IntPtr pProviderInfo,       // SIGNER_PROVIDER_INFO
            string pwszHttpTimeStamp,   // LPCWSTR
            IntPtr psRequest,           // PCRYPT_ATTRIBUTES
            IntPtr pSipData             // LPVOID 
            );

        [DllImport("Mssign32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int SignerSignEx(
            uint dwFlags,               // DWORD
            IntPtr pSubjectInfo,        // SIGNER_SUBJECT_INFO
            IntPtr pSignerCert,         // SIGNER_CERT
            IntPtr pSignatureInfo,      // SIGNER_SIGNATURE_INFO
            IntPtr pProviderInfo,       // SIGNER_PROVIDER_INFO
            string pwszHttpTimeStamp,   // LPCWSTR
            IntPtr psRequest,           // PCRYPT_ATTRIBUTES
            IntPtr pSipData,            // LPVOID 
            out SIGNER_CONTEXT ppSignerContext  // SIGNER_CONTEXT
            );

        [DllImport("Mssign32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int SignerSignEx2(
            uint dwFlags,               // DWORD
            IntPtr pSubjectInfo,        // SIGNER_SUBJECT_INFO
            IntPtr pSignerCert,         // SIGNER_CERT
            IntPtr pSignatureInfo,      // SIGNER_SIGNATURE_INFO
            IntPtr pProviderInfo,       // SIGNER_PROVIDER_INFO
            int dwTimestampFlags,       // DWORD                  
            string pszTimestampAlgOid,  // PCSTR
            string pwszHttpTimeStamp,   // LPCWSTR
            IntPtr psRequest,           // PCRYPT_ATTRIBUTES
            IntPtr pSipData,            // LPVOID 
            out SIGNER_CONTEXT ppSignerContext,  // SIGNER_CONTEXT
            IntPtr PCSTR,               // PCERT_STRONG_SIGN_PARA 
            IntPtr pReserved            // PVOID                  
            );

        [DllImport("Mssign32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int SignerTimeStamp(
            IntPtr pSubjectInfo,        // SIGNER_SUBJECT_INFO
            string pwszHttpTimeStamp,   // LPCWSTR
            IntPtr psRequest,           // PCRYPT_ATTRIBUTES
            IntPtr pSipData             // LPVOID 
            );

        [DllImport("Mssign32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int SignerTimeStampEx(
            uint dwFlags,               // DWORD
            IntPtr pSubjectInfo,        // SIGNER_SUBJECT_INFO
            string pwszHttpTimeStamp,   // LPCWSTR
            IntPtr psRequest,           // PCRYPT_ATTRIBUTES
            IntPtr pSipData,            // LPVOID
            out SIGNER_CONTEXT ppSignerContext  // SIGNER_CONTEXT
            );

        [DllImport("Mssign32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int SignerTimeStampEx2(
           uint dwFlags,               // DWORD
           IntPtr pSubjectInfo,        // SIGNER_SUBJECT_INFO
           string pwszHttpTimeStamp,   // LPCWSTR
           uint dwAlgId,               // ALG_ID
           IntPtr psRequest,           // PCRYPT_ATTRIBUTES
           IntPtr pSipData,            // LPVOID 
           out IntPtr ppSignerContext  // SIGNER_CONTEXT
           );

        [DllImport("Mssign32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int SignerTimeStampEx3(
           uint dwFlags,               // DWORD
           uint dwIndex,               // DWORD
           IntPtr pSubjectInfo,        // SIGNER_SUBJECT_INFO
           string pwszHttpTimeStamp,   // LPCWSTR
           IntPtr dwAlgId,             // ALG_ID
           IntPtr psRequest,           // PCRYPT_ATTRIBUTES
           IntPtr pSipData,            // LPVOID 
           out IntPtr ppSignerContext, // SIGNER_CONTEXT
           IntPtr pCryptoPolicy,       // PCERT_STRONG_SIGN_PARA
           IntPtr pReserved            // PVOID
           );

        [DllImport("Crypt32.dll", EntryPoint = "CertCreateCertificateContext", SetLastError = true, CharSet = CharSet.Unicode, ExactSpelling = false, CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr CertCreateCertificateContext(
            int dwCertEncodingType,
            byte[] pbCertEncoded,
            int cbCertEncoded);

        [DllImport("Crypt32.DLL", EntryPoint = "CertOpenStore", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CertOpenStore(int storeProvider, int encodingType, IntPtr hcryptProv, int flags, String pvPara);

        [DllImport("Crypt32.DLL", EntryPoint = "CertCloseStore", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool CertCloseStore(IntPtr store, int flags);

        [DllImport("CRYPT32.DLL", EntryPoint = "CertAddEncodedCertificateToStore", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CertAddEncodedCertificateToStore(IntPtr certStore, int certEncodingType, byte[] certEncoded, int certEncodedLength, int addDisposition, IntPtr certContext);

        [DllImport("CRYPT32.DLL", EntryPoint = "CertEnumCertificatesInStore", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CertEnumCertificatesInStore(IntPtr storeProvider, IntPtr prevCertContext);

        #endregion

        #region PARAMS

        private static Exception LastError = null;

        #endregion PARAMS

        #region public methods

        public static Exception GetLastError() { return LastError; }

        /// <summary>
        ///     Sign File (Call SignerSignEx and SignerTimeStampEx for a given .pfx / .pem)
        /// </summary>
        /// <param name="filePath"></param>
        /// <param name="certPath"></param>
        /// <param name="certPassword"></param>
        /// <param name="timestampUrl"></param>
        public static bool SignWithCertFile(string filePath, string certPath, string certPassword = null, string timestampUrl = TIME_SERVER_A, uint CALC_ALG = CALG_SHA_256, bool append = false)
        {
            if (CALC_ALG == 0) CALC_ALG = CALG_SHA_256;
            if (string.IsNullOrEmpty(timestampUrl)) timestampUrl = TIME_SERVER_A;
            IntPtr pSignerCert = IntPtr.Zero;
            IntPtr pSubjectInfo = IntPtr.Zero;
            IntPtr pSignatureInfo = IntPtr.Zero;
            IntPtr pProviderInfo = IntPtr.Zero;
            LastError = null;

            try
            {
                X509Certificate2 cert = string.IsNullOrEmpty(certPassword) ? new X509Certificate2(certPath) : new X509Certificate2(certPath, certPassword);
                // -2147024810 Incorrect Passw //                

                pSignerCert = CreateSignerCert(cert, ref append, GetFriendlyAlgoName(CALC_ALG), filePath);
                pSubjectInfo = CreateSignerSubjectInfo(filePath);
                pSignatureInfo = CreateSignerSignatureInfo(CALC_ALG);
                pProviderInfo = GetProviderInfo(cert);

                SIGNER_CONTEXT signerContext;

                uint dwFlags = (uint)(append ? 0x1000 /* SIG_APPEND */ : 0x0000);
                int signRes = _SignerSignEx(dwFlags, pSubjectInfo, pSignerCert, pSignatureInfo, pProviderInfo, out signerContext, append);

                if (signRes == 0 && !string.IsNullOrEmpty(timestampUrl))
                {
                    //signRes = _SignerTimeStamp(pSubjectInfo, timestampUrl);
                    if (!append)
                        signRes = _SignerTimeStampEx(0x0000 /* None */, pSubjectInfo, timestampUrl, out signerContext);
                    else
                    {                        
                        uint dwIndex = 0;
                        try
                        {
                            VertificatePE.GetSignatureFileInfo(filePath, out VertificatePE.VERIFY_SIGNATURE[] sigs, out _);
                            DateTime dt = DateTime.MinValue;
                            if (sigs != null && sigs.Length > 0)
                                for (uint i = 0; i < sigs.Length; i++)
                                {
                                    if (sigs[i].Certificate == null) continue;
                                    if (sigs[i].Certificate.Thumbprint.ToUpper() != cert.Thumbprint.ToUpper()) continue;
                                    if (sigs[i].Signed > dt) { dt = sigs[i].Signed; dwIndex = i; };
                                };
                        }
                        catch { };
                        signRes = _SignerTimeStampEx3((uint)SIGNER_TIMESTAMP_RFC3161, dwIndex, GetFriendlyAlgoID(CALC_ALG), pSubjectInfo, timestampUrl, out signerContext);
                    }
                };

                if (signRes != 0) LastError = new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                return signRes == 0;
            }
            catch (CryptographicException ce)
            {
                int ie = Marshal.GetHRForException(ce);
                switch (ie)
                {
                    case -2146885623:
                        LastError = new Exception(string.Format(@"An error occurred while attempting to load the signing certificate.  {1} ""{0}"" does not appear to contain a valid certificate.", certPath, ie));
                        break;
                    case -2147024810:
                        LastError = new Exception(string.Format(@"An error occurred while attempting to load the signing certificate.  {0} The specified password was incorrect.", ie));
                        break;
                    default:
                        LastError = new Exception(string.Format(@"An error occurred while attempting to load the signing certificate.  {1} {0}", ce.Message, ie));
                        break;
                };
            }
            catch (Exception e) { LastError = e; }
            finally
            {
                if (pSignerCert != IntPtr.Zero)
                    Marshal.DestroyStructure(pSignerCert, typeof(SIGNER_CERT));
                if (pSubjectInfo != IntPtr.Zero)
                    Marshal.DestroyStructure(pSubjectInfo, typeof(SIGNER_SUBJECT_INFO));
                if (pSignatureInfo != IntPtr.Zero)
                    Marshal.DestroyStructure(pSignatureInfo, typeof(SIGNER_SIGNATURE_INFO));
                if (pProviderInfo != IntPtr.Zero)
                    Marshal.DestroyStructure(pSignatureInfo, typeof(SIGNER_PROVIDER_INFO));
            };
            return false;
        }

        /// <summary>
        ///     Sign File (Call SignerSign and SignerTimeStamp for a given thumbprint)
        /// </summary>
        /// <param name="filePath"></param>
        /// <param name="thumbprint"></param>
        /// <param name="timestampUrl"></param>
        public static bool SignWithThumbprint(string filePath, string thumbprint, string timestampUrl = TIME_SERVER_A, uint CALC_ALG = CALG_SHA_256, bool append = false)
        {
            if (CALC_ALG == 0) CALC_ALG = CALG_SHA_256;
            if (string.IsNullOrEmpty(timestampUrl)) timestampUrl = TIME_SERVER_A;
            IntPtr pSignerCert = IntPtr.Zero;
            IntPtr pSubjectInfo = IntPtr.Zero;
            IntPtr pSignatureInfo = IntPtr.Zero;
            IntPtr pProviderInfo = IntPtr.Zero;
            LastError = null;

            try
            {
                X509Certificate2 cert = FindCertByThumbprint(thumbprint);

                pSignerCert = CreateSignerCert(cert, ref append, GetFriendlyAlgoName(CALC_ALG), filePath);
                pSubjectInfo = CreateSignerSubjectInfo(filePath);
                pSignatureInfo = CreateSignerSignatureInfo(CALC_ALG);
                pProviderInfo = GetProviderInfo(cert);

                SIGNER_CONTEXT signerContext;

                uint dwFlags = (uint)(append ? 0x1000 /* SIG_APPEND */ : 0x0000);
                int signRes = _SignerSignEx(dwFlags, pSubjectInfo, pSignerCert, pSignatureInfo, pProviderInfo, out signerContext, append);

                if (signRes == 0 && !string.IsNullOrEmpty(timestampUrl))
                {
                    //signRes = _SignerTimeStamp(pSubjectInfo, timestampUrl);
                    if (!append)
                        signRes = _SignerTimeStampEx(0x0000 /* None */, pSubjectInfo, timestampUrl, out signerContext);
                    else
                    {
                        uint dwIndex = 0;
                        try
                        {
                            VertificatePE.GetSignatureFileInfo(filePath, out VertificatePE.VERIFY_SIGNATURE[] sigs, out _);
                            DateTime dt = DateTime.MinValue;
                            if (sigs != null && sigs.Length > 0)
                                for (uint i = 0; i < sigs.Length; i++)
                                {
                                    if (sigs[i].Certificate == null) continue;
                                    if (sigs[i].Certificate.Thumbprint.ToUpper() != cert.Thumbprint.ToUpper()) continue;
                                    if (sigs[i].Signed > dt) { dt = sigs[i].Signed; dwIndex = i; };
                                };
                        }
                        catch { };
                        signRes = _SignerTimeStampEx3((uint)SIGNER_TIMESTAMP_RFC3161, dwIndex, GetFriendlyAlgoID(CALC_ALG), pSubjectInfo, timestampUrl, out signerContext);
                    }
                };

                if (signRes != 0) LastError = new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                return signRes == 0;
            }
            catch (CryptographicException ce)
            {
                int ie = Marshal.GetHRForException(ce);
                switch (ie)
                {
                    case -2146885623:
                        LastError = new Exception(string.Format(@"An error occurred while attempting to load the signing certificate.  {1} ""{0}"" does not locate to a valid certificate.", thumbprint, ie));
                        break;
                    case -2147024810:
                        LastError = new Exception(string.Format(@"An error occurred while attempting to load the signing certificate.  {0} The specified password was incorrect.", ie));
                        break;
                    default:
                        LastError = new Exception(string.Format(@"An error occurred while attempting to load the signing certificate.  {1} {0}", ce.Message, ie));
                        break;
                };
            }
            catch (Exception e) { LastError = e; }
            finally
            {
                if (pSignerCert != IntPtr.Zero)
                    Marshal.DestroyStructure(pSignerCert, typeof(SIGNER_CERT));
                if (pSubjectInfo != IntPtr.Zero)
                    Marshal.DestroyStructure(pSubjectInfo, typeof(SIGNER_SUBJECT_INFO));
                if (pSignatureInfo != IntPtr.Zero)
                    Marshal.DestroyStructure(pSignatureInfo, typeof(SIGNER_SIGNATURE_INFO));
                if (pProviderInfo != IntPtr.Zero)
                    Marshal.DestroyStructure(pSignatureInfo, typeof(SIGNER_PROVIDER_INFO));
            };
            return false;
        }

        public static object ExtractPublicKey(X509Certificate2 cert)
        {
            switch (cert.PublicKey.Oid.Value)
            {
                case CALO_RSA: return (RSA)cert.GetRSAPublicKey();
                case CALO_DSA: return (DSA)cert.GetDSAPublicKey();
                case CALO_ECC: return (ECDsa)cert.GetECDsaPublicKey();
                default: break;
            };
            return cert.PublicKey;
        }

        public static AsymmetricAlgorithm ExtractPrivateKey(X509Certificate2 cert)
        {
            switch (cert.PublicKey.Oid.Value)
            {
                case CALO_RSA: return (RSA)cert.GetRSAPrivateKey();
                case CALO_DSA: return (DSA)cert.GetDSAPrivateKey();
                case CALO_ECC: return (ECDsa)cert.GetECDsaPrivateKey();
                default: break;
            };
            return cert.PrivateKey;
        }

        public static RSACryptoServiceProvider ExtractRsaPrivateKey(X509Certificate2 cert)
        {
            const string RSA = "1.2.840.113549.1.1.1";
            switch (cert.PublicKey.Oid.Value)
            {
                case RSA: return (RSACryptoServiceProvider)cert.GetRSAPrivateKey();
                default: break;
            };
            return cert.PrivateKey as RSACryptoServiceProvider;
        }

        public static string GetFriendlyAlgoName(uint CAL_ALG)
        {
            if (CAL_ALG == CALG_MD5) return CALN_MD5;
            if (CAL_ALG == CALG_SHA1) return CALN_SHA1;
            if (CAL_ALG == CALG_SHA_256) return CALN_SHA_256;
            if (CAL_ALG == CALG_SHA_512) return CALN_SHA_512;
            return "unknown";
        }

        public static string GetFriendlyAlgoID(uint CAL_ALG)
        {
            if (CAL_ALG == CALG_MD5) return CALO_MD5;
            if (CAL_ALG == CALG_SHA1) return CALO_SHA1;
            if (CAL_ALG == CALG_SHA_256) return CALO_SHA_256;
            if (CAL_ALG == CALG_SHA_512) return CALO_SHA_512;
            return "unknown";
        }

        private static IntPtr CreateSignerSubjectInfo(string pathToAssembly)
        {
            SIGNER_SUBJECT_INFO info = new SIGNER_SUBJECT_INFO
            {
                cbSize = (uint)Marshal.SizeOf(typeof(SIGNER_SUBJECT_INFO)),
                pdwIndex = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(uint)))
            };

            Marshal.StructureToPtr((int)0, info.pdwIndex, false);

            info.dwSubjectChoice = SIGNER_SUBJECT_FILE;
            IntPtr assemblyFilePtr = Marshal.StringToHGlobalUni(pathToAssembly);

            SIGNER_FILE_INFO fileInfo = new SIGNER_FILE_INFO
            {
                cbSize = (uint)Marshal.SizeOf(typeof(SIGNER_FILE_INFO)),
                pwszFileName = assemblyFilePtr,
                hFile = IntPtr.Zero
            };

            info.Union1 = new SIGNER_SUBJECT_INFO.SubjectChoiceUnion
            {
                pSignerFileInfo = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SIGNER_FILE_INFO)))
            };

            Marshal.StructureToPtr(fileInfo, info.Union1.pSignerFileInfo, false);

            IntPtr pSubjectInfo = Marshal.AllocHGlobal(Marshal.SizeOf(info));
            Marshal.StructureToPtr(info, pSubjectInfo, false);

            return pSubjectInfo;
        }

        private static X509Certificate2 FindCertByThumbprint(string thumbprint)
        {
            try
            {
                string thumbprintFixed = thumbprint.Replace(" ", string.Empty).ToUpperInvariant();

                X509Store[] stores = new X509Store[4] { new X509Store(StoreName.My, StoreLocation.CurrentUser),
                                                        new X509Store(StoreName.My, StoreLocation.LocalMachine),
                                                        new X509Store(StoreName.TrustedPublisher, StoreLocation.CurrentUser),
                                                        new X509Store(StoreName.TrustedPublisher, StoreLocation.LocalMachine) };

                foreach (X509Store store in stores)
                {
                    store.Open(OpenFlags.ReadOnly);
                    X509Certificate2Collection certs = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprintFixed, false);
                    store.Close();
                    if (certs.Count < 1) continue;
                    return certs[0];
                };

                throw new Exception(string.Format(@"A certificate matching the thumbprint: ""{0}"" could not be found.  Make sure that a valid certificate matching the provided thumbprint is installed.", thumbprint));
            }
            catch (Exception e) { throw e; };
        }

        private static IntPtr CreateSignerCert(X509Certificate2 cert, ref bool append, string algo = "sha256", string sourceFile = null)
        {
            SIGNER_CERT signerCert = new SIGNER_CERT
            {
                cbSize = (uint)Marshal.SizeOf(typeof(SIGNER_CERT)),
                dwCertChoice = SIGNER_CERT_STORE,
                Union1 = new SIGNER_CERT.SignerCertUnion
                {
                    pCertStoreInfo = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SIGNER_CERT_STORE_INFO)))
                },
                hwnd = IntPtr.Zero
            };

            IntPtr pCertContext = CertCreateCertificateContext(
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                cert.GetRawCertData(),
                cert.GetRawCertData().Length);

            IntPtr pCertStore = IntPtr.Zero;
            if (append)
            {
                append = false;
                if (!string.IsNullOrEmpty(sourceFile) && File.Exists(sourceFile))
                {
                    VertificatePE.GetSignatureFileInfo(sourceFile, out VertificatePE.VERIFY_SIGNATURE[] sigs, out _);
                    if (sigs != null && sigs.Length > 0)
                    {
                        pCertStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, IntPtr.Zero, CERT_STORE_CREATE_NEW_FLAG, null);
                        if (pCertStore != IntPtr.Zero)
                        {
                            foreach (VertificatePE.VERIFY_SIGNATURE sig in sigs)
                            {
                                if (sig.Certificate == null) continue;
                                string hashAlg = sig.HashAlgorithm.FriendlyName.ToUpper();
                                byte[] cData = sig.Certificate.GetRawCertData();
                                if (CertAddEncodedCertificateToStore(pCertStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, cData, cData.Length, CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES, IntPtr.Zero))
                                    append = true;
                            };
                            if (append)
                            {
                                byte[] cData = cert.GetRawCertData();
                                CertAddEncodedCertificateToStore(pCertStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, cData, cData.Length, CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES, IntPtr.Zero);
                            }
                            else
                            {
                                if (pCertStore != IntPtr.Zero) CertCloseStore(pCertStore, 0);
                                pCertStore = IntPtr.Zero;
                            };
                        };
                    };                                   
                };
            };

            SIGNER_CERT_STORE_INFO certStoreInfo = new SIGNER_CERT_STORE_INFO
            {
                cbSize = (uint)Marshal.SizeOf(typeof(SIGNER_CERT_STORE_INFO)),
                pSigningCert = pCertContext,
                dwCertPolicy = SIGNER_CERT_POLICY_CHAIN,
                hCertStore = pCertStore
            };

            Marshal.StructureToPtr(certStoreInfo, signerCert.Union1.pCertStoreInfo, false);

            IntPtr pSignerCert = Marshal.AllocHGlobal(Marshal.SizeOf(signerCert));
            Marshal.StructureToPtr(signerCert, pSignerCert, false);

            return pSignerCert;
        }

        private static IntPtr CreateSignerSignatureInfo(uint CALC_ALG = CALG_SHA_256)
        {
            SIGNER_SIGNATURE_INFO signatureInfo = new SIGNER_SIGNATURE_INFO
            {
                cbSize = (uint)Marshal.SizeOf(typeof(SIGNER_SIGNATURE_INFO)),
                algidHash = CALC_ALG,
                dwAttrChoice = SIGNER_NO_ATTR,
                pAttrAuthCode = IntPtr.Zero,
                psAuthenticated = IntPtr.Zero,
                psUnauthenticated = IntPtr.Zero
            };

            IntPtr pSignatureInfo = Marshal.AllocHGlobal(Marshal.SizeOf(signatureInfo));
            Marshal.StructureToPtr(signatureInfo, pSignatureInfo, false);

            return pSignatureInfo;
        }

        private static IntPtr GetProviderInfo(X509Certificate2 cert)
        {
            if (cert == null || !cert.HasPrivateKey) return IntPtr.Zero;

            ICspAsymmetricAlgorithm key = (ICspAsymmetricAlgorithm)cert.PrivateKey;            

            if (key == null) return IntPtr.Zero;

            SIGNER_PROVIDER_INFO providerInfo = new SIGNER_PROVIDER_INFO
            {
                cbSize = (uint)Marshal.SizeOf(typeof(SIGNER_PROVIDER_INFO)),
                pwszProviderName = Marshal.StringToHGlobalUni(key.CspKeyContainerInfo.ProviderName),
                dwProviderType = (uint)key.CspKeyContainerInfo.ProviderType,
                dwPvkChoice = PVK_TYPE_KEYCONTAINER,
                Union1 = new SIGNER_PROVIDER_INFO.SignerProviderUnion
                {
                    pwszKeyContainer = Marshal.StringToHGlobalUni(key.CspKeyContainerInfo.KeyContainerName)
                },
            };

            IntPtr pProviderInfo = Marshal.AllocHGlobal(Marshal.SizeOf(providerInfo));
            Marshal.StructureToPtr(providerInfo, pProviderInfo, false);

            return pProviderInfo;
        }

        #region SignerSign

        private static int _SignerSign(uint dwFlags, IntPtr pSubjectInfo, IntPtr pSignerCert, IntPtr pSignatureInfo, IntPtr pProviderInfo, bool multisign_ex2 = false)
        {
            int hResult = OK_RESULT;
            if (!multisign_ex2)
            {
                hResult = SignerSign(
                    pSubjectInfo,
                    pSignerCert,
                    pSignatureInfo,
                    pProviderInfo,
                    null,
                    IntPtr.Zero,
                    IntPtr.Zero
                    );
            }
            else
            {
                hResult = SignerSignEx2(
                    dwFlags,
                    pSubjectInfo,
                    pSignerCert,
                    pSignatureInfo,
                    pProviderInfo,
                    SIGNER_TIMESTAMP_RFC3161,
                    null,
                    null,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    out SIGNER_CONTEXT signerContext,
                    IntPtr.Zero,
                    IntPtr.Zero
                    );
            };

            if (hResult != OK_RESULT)
                Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
            return hResult;
        }

        private static int _SignerSignEx(uint dwFlags, IntPtr pSubjectInfo, IntPtr pSignerCert, IntPtr pSignatureInfo, IntPtr pProviderInfo, out SIGNER_CONTEXT signerContext, bool multisign_ex2 = false)
        {
            int hResult = OK_RESULT;
            if (!multisign_ex2)
            {

                hResult = SignerSignEx(
                dwFlags,
                pSubjectInfo,
                pSignerCert,
                pSignatureInfo,
                pProviderInfo,
                null,
                IntPtr.Zero,
                IntPtr.Zero,
                out signerContext
                );
            }
            else
            {
                hResult = SignerSignEx2(
                    dwFlags,
                    pSubjectInfo,
                    pSignerCert,
                    pSignatureInfo,
                    pProviderInfo,
                    SIGNER_TIMESTAMP_RFC3161,
                    null,
                    null,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    out signerContext,
                    IntPtr.Zero,
                    IntPtr.Zero
                    );
            };

            if (hResult != OK_RESULT)
                Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
            return hResult;
        }

        #endregion SignerSign

        #region SignerTimeStamp

        private static int _SignerTimeStamp(IntPtr pSubjectInfo, string timestampUrl)
        {
            int hResult = SignerTimeStamp(pSubjectInfo, timestampUrl, IntPtr.Zero, IntPtr.Zero);
            if (hResult != OK_RESULT)
            {
                //Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
                throw new Exception(string.Format(@"""{0}"" could not be used at this time.  If necessary, check the timestampUrl, internet connection, and try again.", timestampUrl));
            };
            return hResult;
        }

        private static int _SignerTimeStampEx(uint dwFlags, IntPtr pSubjectInfo, string timestampUrl, out SIGNER_CONTEXT signerContext)
        {
            //signerContext = new SIGNER_CONTEXT();
            //int rr = SignerTimeStampEx2(dwFlags, pSubjectInfo, timestampUrl, 0x0000800c, IntPtr.Zero, IntPtr.Zero, out IntPtr sc);
            //return rr;

            int hResult = SignerTimeStampEx(dwFlags, pSubjectInfo, timestampUrl, IntPtr.Zero, IntPtr.Zero, out signerContext);
            if (hResult != OK_RESULT)
            {
                //Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
                throw new Exception(string.Format(@"""{0}"" could not be used at this time.  If necessary, check the timestampUrl, internet connection, and try again.", timestampUrl));
            };
            return hResult;
        }

        private static int _SignerTimeStampEx3(uint dwFlags, uint dwIndex, string algo, IntPtr pSubjectInfo, string timestampUrl, out SIGNER_CONTEXT signerContext)
        {
            //signerContext = new SIGNER_CONTEXT();
            //int rr = SignerTimeStampEx2(dwFlags, pSubjectInfo, timestampUrl, 0x0000800c, IntPtr.Zero, IntPtr.Zero, out IntPtr sc);
            //return rr;

            signerContext = new SIGNER_CONTEXT();
            int hResult = SignerTimeStampEx3(dwFlags, dwIndex, pSubjectInfo, timestampUrl, Marshal.StringToHGlobalAnsi(algo), IntPtr.Zero, IntPtr.Zero, out IntPtr sc, IntPtr.Zero, IntPtr.Zero);
            if (hResult != OK_RESULT)
            {
                //Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
                throw new Exception(string.Format(@"""{0}"" could not be used at this time.  If necessary, check the timestampUrl, internet connection, and try again.", timestampUrl));
            };
            return hResult;
        }

        #endregion SignerTimeStamp

        #endregion private methods
    }
}