//
// C# 
// dkxce.SignificatePE
// http://github.com/dkxce/SignificatePE
// en,ru,1251,utf-8
//

using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace dkxce
{
    public static class SignificatePE
    {
        #region TIME SERVERS

        private const string TIME_SERVER_A = "http://timestamp.digicert.com";
        private const string TIME_SERVER_B = "http://timestamp.comodoca.com";

        #endregion TIME SERVERS

        #region CONSTS

        #region algidHash

        private const uint CALG_NO_SIGN = 0x00002000;
        private const uint CALG_MD5 = 0x00008003;
        private const uint CALG_SHA = 0x00008004;
        private const uint CALG_SHA1 = 0x00008004;
        private const uint CALG_SHA_256 = 0x0000800c;
        private const uint CALG_SHA_512 = 0x0000800e;

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

        [DllImport("Crypt32.dll", EntryPoint = "CertCreateCertificateContext", SetLastError = true, CharSet = CharSet.Unicode, ExactSpelling = false, CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr CertCreateCertificateContext(
            int dwCertEncodingType,
            byte[] pbCertEncoded,
            int cbCertEncoded);

        #endregion

        #region PARAMS

        private static Exception LastError = null;

        #endregion PARAMS

        #region public methods

        public static Exception GetLastError() { return LastError; }

        /// <summary>
        ///     Sign File (Call SignerSignEx and SignerTimeStampEx for a given .pfx)
        /// </summary>
        /// <param name="filePath"></param>
        /// <param name="certPath"></param>
        /// <param name="certPassword"></param>
        /// <param name="timestampUrl"></param>
        public static bool SignWithCert(string filePath, string certPath, string certPassword = null, string timestampUrl = TIME_SERVER_A, uint CALC_ALG = CALG_SHA_256)
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

                pSignerCert = CreateSignerCert(cert);
                pSubjectInfo = CreateSignerSubjectInfo(filePath);
                pSignatureInfo = CreateSignerSignatureInfo(CALC_ALG);
                pProviderInfo = GetProviderInfo(cert);

                SIGNER_CONTEXT signerContext;

                int signRes = _SignerSignEx(0x0, pSubjectInfo, pSignerCert, pSignatureInfo, pProviderInfo, out signerContext);

                if (signRes == 0 && !string.IsNullOrEmpty(timestampUrl))
                    signRes = _SignerTimeStampEx(0x0, pSubjectInfo, timestampUrl, out signerContext);

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
        public static bool SignWithThumbprint(string filePath, string thumbprint, string timestampUrl = TIME_SERVER_A, uint CALC_ALG = CALG_SHA_256)
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
                pSignerCert = CreateSignerCert(thumbprint);
                pSubjectInfo = CreateSignerSubjectInfo(filePath);
                pSignatureInfo = CreateSignerSignatureInfo(CALC_ALG);

                int signRes = _SignerSign(pSubjectInfo, pSignerCert, pSignatureInfo, pProviderInfo);

                if (signRes == 0 && !string.IsNullOrEmpty(timestampUrl))
                    signRes = _SignerTimeStamp(pSubjectInfo, timestampUrl);
                
                if(signRes != 0) LastError = new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                return signRes == 0;
            }
            catch (CryptographicException ce) { LastError = new Exception(string.Format(@"An error occurred while attempting to load the signing certificate.  {0}", ce.Message)); }
            catch (Exception e) { LastError = e; }
            finally
            {
                if (pSignerCert != IntPtr.Zero)
                    Marshal.DestroyStructure(pSignerCert, typeof(SIGNER_CERT));
                if (pSubjectInfo != IntPtr.Zero)
                    Marshal.DestroyStructure(pSubjectInfo, typeof(SIGNER_SUBJECT_INFO));
                if (pSignatureInfo != IntPtr.Zero)
                    Marshal.DestroyStructure(pSignatureInfo, typeof(SIGNER_SIGNATURE_INFO));
            };
            return false;
        }

        public static object ExtractPublicKey(X509Certificate2 cert)
        {
            const string RSA = "1.2.840.113549.1.1.1";
            const string DSA = "1.2.840.10040.4.1";
            const string ECC = "1.2.840.10045.2.1";
            switch (cert.PublicKey.Oid.Value)
            {
                case RSA:
                    return (RSA)cert.GetRSAPublicKey();
                case DSA:
                    return (DSA)cert.GetDSAPublicKey();
                case ECC:
                    return (ECDsa)cert.GetECDsaPublicKey();
                default:
                    break;
            };
            return cert.PublicKey;
        }

        public static AsymmetricAlgorithm ExtractPrivateKey(X509Certificate2 cert)
        {
            const string RSA = "1.2.840.113549.1.1.1";
            const string DSA = "1.2.840.10040.4.1";
            const string ECC = "1.2.840.10045.2.1";
            switch (cert.PublicKey.Oid.Value)
            {
                case RSA:
                    return (RSA)cert.GetRSAPrivateKey();
                case DSA:
                    return (DSA)cert.GetDSAPrivateKey();
                case ECC:
                    return (ECDsa)cert.GetECDsaPrivateKey();
                default:
                    break;
            };
            return cert.PrivateKey;
        }

        public static RSACryptoServiceProvider ExtractRsaPrivateKey(X509Certificate2 cert)
        {
            const string RSA = "1.2.840.113549.1.1.1";
            switch (cert.PublicKey.Oid.Value)
            {
                case RSA:
                    return (RSACryptoServiceProvider)cert.GetRSAPrivateKey();
                default:
                    break;
            };
            return cert.PrivateKey as RSACryptoServiceProvider;
        }

        #endregion public methods

        #region private methods

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

        private static IntPtr CreateSignerCert(X509Certificate2 cert)
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

            SIGNER_CERT_STORE_INFO certStoreInfo = new SIGNER_CERT_STORE_INFO
            {
                cbSize = (uint)Marshal.SizeOf(typeof(SIGNER_CERT_STORE_INFO)),
                pSigningCert = pCertContext,
                dwCertPolicy = SIGNER_CERT_POLICY_CHAIN,
                hCertStore = IntPtr.Zero
            };

            Marshal.StructureToPtr(certStoreInfo, signerCert.Union1.pCertStoreInfo, false);

            IntPtr pSignerCert = Marshal.AllocHGlobal(Marshal.SizeOf(signerCert));
            Marshal.StructureToPtr(signerCert, pSignerCert, false);

            return pSignerCert;
        }

        private static IntPtr CreateSignerCert(string thumbprint)
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

            X509Certificate2 cert = FindCertByThumbprint(thumbprint);

            IntPtr pCertContext = CertCreateCertificateContext(
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                cert.GetRawCertData(),
                cert.GetRawCertData().Length);

            SIGNER_CERT_STORE_INFO certStoreInfo = new SIGNER_CERT_STORE_INFO
            {
                cbSize = (uint)Marshal.SizeOf(typeof(SIGNER_CERT_STORE_INFO)),
                pSigningCert = pCertContext,
                dwCertPolicy = SIGNER_CERT_POLICY_CHAIN,
                hCertStore = IntPtr.Zero
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
            const int PVK_TYPE_KEYCONTAINER = 2;

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

        private static int _SignerSign(IntPtr pSubjectInfo, IntPtr pSignerCert, IntPtr pSignatureInfo, IntPtr pProviderInfo)
        {
            int hResult = SignerSign(
                pSubjectInfo,
                pSignerCert,
                pSignatureInfo,
                pProviderInfo,
                null,
                IntPtr.Zero,
                IntPtr.Zero
                );

            if (hResult != 0)
                Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
            return hResult;
        }

        private static int _SignerSignEx(uint dwFlags, IntPtr pSubjectInfo, IntPtr pSignerCert, IntPtr pSignatureInfo, IntPtr pProviderInfo, out SIGNER_CONTEXT signerContext)
        {

            int hResult = SignerSignEx(
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

            if (hResult != 0)
                Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
            return hResult;
        }

        private static int _SignerTimeStamp(IntPtr pSubjectInfo, string timestampUrl)
        {
            int hResult = SignerTimeStamp(pSubjectInfo, timestampUrl, IntPtr.Zero, IntPtr.Zero);
            if (hResult != 0)
            {
                //Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
                throw new Exception(string.Format(@"""{0}"" could not be used at this time.  If necessary, check the timestampUrl, internet connection, and try again.", timestampUrl));
            };
            return hResult;
        }

        private static int _SignerTimeStampEx(uint dwFlags, IntPtr pSubjectInfo, string timestampUrl, out SIGNER_CONTEXT signerContext)
        {
            int hResult = SignerTimeStampEx(dwFlags, pSubjectInfo, timestampUrl, IntPtr.Zero, IntPtr.Zero, out signerContext);
            if (hResult != 0)
            {
                //Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
                throw new Exception(string.Format(@"""{0}"" could not be used at this time.  If necessary, check the timestampUrl, internet connection, and try again.", timestampUrl));
            };
            return hResult;
        }

        #endregion private methods
    }
}