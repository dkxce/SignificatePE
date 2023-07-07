//
// C# 
// dkxce.VertificatePE
// http://github.com/dkxce/SignificatePE
// en,ru,1251,utf-8
//

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Text;

namespace dkxce
{
    public static class VertificatePE
    {
        // http://www.heaventools.com/pe-explorer-digital-signature.htm
        // https://learn.microsoft.com/ru-ru/sysinternals/downloads/sigcheck
        // https://security.stackexchange.com/questions/50959/how-to-check-executable-code-signing-signatures
        // https://github.com/SummitRoute/osslsigncode-fork

        #region Constants

        private const uint GENERIC_READ = 0x80000000;
        private const uint GENERIC_WRITE = 0x40000000;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint FILE_SHARE_DELETE = 0x00000004;
        private const uint OPEN_EXISTING = 3;
        private const uint CERT_SECTION_TYPE_ANY = 255;
        private const string WINTRUST_ACTION_GENERIC_VERIFY_V2 = "{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}";
        private const short INVALID_HANDLE_VALUE = -1;

        private const int SGNR_TYPE_TIMESTAMP = 0x00000010;
        private const int WTD_UI_NONE = 2;
        private const int WTD_CHOICE_FILE = 1;
        private const int WTD_REVOKE_NONE = 0;
        private const int WTD_REVOKE_WHOLECHAIN = 1;
        private const int WTD_STATEACTION_IGNORE = 0;
        private const int WTD_STATEACTION_VERIFY = 1;
        private const int WTD_STATEACTION_CLOSE = 2;
        private const int WTD_REVOCATION_CHECK_NONE = 16;
        private const int WTD_REVOCATION_CHECK_CHAIN = 64;
        private const int WTD_UICONTEXT_EXECUTE = 0;
        private const int WSS_VERIFY_SPECIFIC = 0x00000001;
        private const int WSS_GET_SECONDARY_SIG_COUNT = 0x00000002;

        private const int X509_ASN_ENCODING = 1;
        private const int CERT_SIMPLE_NAME_STR = 1;
        private const int CERT_OID_NAME_STR = 2;
        private const int CERT_NAME_STR_CRLF_FLAG = 0x08000000;
        private const int CERT_NAME_STR_NO_QUOTING_FLAG = 0x10000000;
        private const int CERT_NAME_STR_REVERSE_FLAG = 0x02000000;

        #endregion Constants

        #region WinVerify

        #region WinTrustData
        private enum WinTrustDataUIChoice : uint
        {
            All = 1,
            None = 2,
            NoBad = 3,
            NoGood = 4
        }

        private enum WinTrustDataRevocationChecks : uint
        {
            None = 0x00000000,
            WholeChain = 0x00000001
        }

        private enum WinTrustDataChoice : uint
        {
            File = 1,
            Catalog = 2,
            Blob = 3,
            Signer = 4,
            Certificate = 5
        }

        private enum WinTrustDataStateAction : uint
        {
            Ignore = 0x00000000,
            Verify = 0x00000001,
            Close = 0x00000002,
            AutoCache = 0x00000003,
            AutoCacheFlush = 0x00000004
        }

        [FlagsAttribute]
        private enum WinTrustDataProvFlags : uint
        {
            UseIe4TrustFlag = 0x00000001,
            NoIe4ChainFlag = 0x00000002,
            NoPolicyUsageFlag = 0x00000004,
            RevocationCheckNone = 0x00000010,
            RevocationCheckEndCert = 0x00000020,
            RevocationCheckChain = 0x00000040,
            RevocationCheckChainExcludeRoot = 0x00000080,
            SaferFlag = 0x00000100,        // Used by software restriction policies. Should not be used.
            HashOnlyFlag = 0x00000200,
            UseDefaultOsverCheck = 0x00000400,
            LifetimeSigningFlag = 0x00000800,
            CacheOnlyUrlRetrieval = 0x00001000,      // affects CRL retrieval and AIA retrieval
            DisableMD2andMD4 = 0x00002000      // Win7 SP1+: Disallows use of MD2 or MD4 in the chain except for the root
        }

        private enum WinTrustDataUIContext : uint
        {
            Execute = 0,
            Install = 1
        }

        #endregion WinTrustData

        #region WinTrustStructures

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private class WinTrustFileInfo
        {
            public UInt32 StructSize = (UInt32)Marshal.SizeOf(typeof(WinTrustFileInfo));
            public IntPtr pszFilePath;                     // required, file name to be verified
            public IntPtr hFile = IntPtr.Zero;             // optional, open handle to FilePath
            public IntPtr pgKnownSubject = IntPtr.Zero;    // optional, subject type if it is known

            public WinTrustFileInfo(String _filePath)
            {
                pszFilePath = Marshal.StringToCoTaskMemAuto(_filePath);
            }
            public void Dispose()
            {
                if (pszFilePath != IntPtr.Zero)
                {
                    Marshal.FreeCoTaskMem(pszFilePath);
                    pszFilePath = IntPtr.Zero;
                }
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private class WinTrustData
        {
            public UInt32 StructSize = (UInt32)Marshal.SizeOf(typeof(WinTrustData));
            public IntPtr PolicyCallbackData = IntPtr.Zero;
            public IntPtr SIPClientData = IntPtr.Zero;
            // required: UI choice
            public WinTrustDataUIChoice UIChoice = WinTrustDataUIChoice.None;
            // required: certificate revocation check options
            public WinTrustDataRevocationChecks RevocationChecks = WinTrustDataRevocationChecks.None;
            // required: which structure is being passed in?
            public WinTrustDataChoice UnionChoice = WinTrustDataChoice.File;
            // individual file
            public IntPtr FileInfoPtr;
            public WinTrustDataStateAction StateAction = WinTrustDataStateAction.Ignore;
            public IntPtr StateData = IntPtr.Zero;
            public String URLReference = null;
            public WinTrustDataProvFlags ProvFlags = WinTrustDataProvFlags.RevocationCheckChainExcludeRoot;
            public WinTrustDataUIContext UIContext = WinTrustDataUIContext.Execute;
            public IntPtr pSignatureSettings;

            // constructor for silent WinTrustDataChoice.File check
            public WinTrustData(WinTrustFileInfo _fileInfo)
            {
                // On Win7SP1+, don't allow MD2 or MD4 signatures
                if ((Environment.OSVersion.Version.Major > 6) ||
                    ((Environment.OSVersion.Version.Major == 6) && (Environment.OSVersion.Version.Minor > 1)) ||
                    ((Environment.OSVersion.Version.Major == 6) && (Environment.OSVersion.Version.Minor == 1) && !String.IsNullOrEmpty(Environment.OSVersion.ServicePack)))
                {
                    ProvFlags |= WinTrustDataProvFlags.DisableMD2andMD4;
                }

                WinTrustFileInfo wtfiData = _fileInfo;
                FileInfoPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf(typeof(WinTrustFileInfo)));
                Marshal.StructureToPtr(wtfiData, FileInfoPtr, false);
            }
            public void Dispose()
            {
                if (FileInfoPtr != IntPtr.Zero)
                {
                    Marshal.FreeCoTaskMem(FileInfoPtr);
                    FileInfoPtr = IntPtr.Zero;
                }
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WinTrustSignatureSettings
        {
            public int cbStruct;
            public int dwIndex;
            public int dwFlags;
            public int cSecondarySigs;
            public int dwVerifiedSigIndex;
            public IntPtr pCryptoPolicy;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CryptProviderData
        {
            public int cbStruct;
            public IntPtr pWintrustData;
            public bool fOpenedFile;
            public IntPtr hWndParent;
            public IntPtr pgActionID;
            public IntPtr hProv;
            public int dwError;
            public int dwRegSecuritySettings;
            public int dwRegPolicySettings;
            public IntPtr psPfns;
            public int cdwTrustStepErrors;
            public IntPtr padwTrustStepErrors;
            public int chStores;
            public IntPtr pahStores;
            public int dwEncoding;
            public IntPtr hMsg;
            public int csSigners;
            public IntPtr pasSigners;
            public int csProvPrivData;
            public IntPtr pasProvPrivData;
            public int dwSubjectChoice;
            public IntPtr pPDSip;
            public IntPtr pszUsageOID;
            public bool fRecallWithState;
            public System.Runtime.InteropServices.ComTypes.FILETIME sftSystemTime;
            public IntPtr pszCTLSignerUsageOID;
            public int dwProvFlags;
            public int dwFinalError;
            public IntPtr pRequestUsage;
            public int dwTrustPubSettings;
            public int dwUIStateFlags;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CryptProviderSgnr
        {
            public int cbStruct;
            public System.Runtime.InteropServices.ComTypes.FILETIME sftVerifyAsOf;
            public int csCertChain;
            public IntPtr pasCertChain;
            public int dwSignerType;
            public IntPtr psSigner;
            public int dwError;
            public int csCounterSigners;
            public IntPtr pasCounterSigners;
            public IntPtr pChainContext;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CryptProviderCert
        {
            public int cbStruct;
            public IntPtr pCert;
            public bool fCommercial;
            public bool fTrustedRoot;
            public bool fSelfSigned;
            public bool fTestCert;
            public int dwRevokedReason;
            public int dwConfidence;
            public int dwError;
            public IntPtr pTrustListContext;
            public bool fTrustListSignerCert;
            public IntPtr pCtlContext;
            public int dwCtlError;
            public bool fIsCyclic;
            public IntPtr pChainElement;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CMSG_SIGNER_INFO
        {
            public int dwVersion;
            public CRYPT_INTEGER_BLOB Issuer;
            public CRYPT_INTEGER_BLOB SerialNumber;
            public CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
            public CRYPT_ALGORITHM_IDENTIFIER HashEncryptionAlgorithm;
            public CRYPT_INTEGER_BLOB EncryptedHash;
            public CRYPT_ATTRIBUTES AuthAttrs;
            public CRYPT_ATTRIBUTES UnauthAttrs;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CRYPT_ALGORITHM_IDENTIFIER
        {
            public IntPtr pszObjId;
            public CRYPT_INTEGER_BLOB Parameters;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CRYPT_INTEGER_BLOB
        {
            public int cbData;
            public IntPtr pbData;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CRYPT_ATTRIBUTES
        {
            public int cAttr;
            public IntPtr rgAttr;
        }

        #endregion WinTrustStructures

        #region WinTrustResult
        public enum WinVerifyTrustResult : uint
        {
            Success = 0,
            //ProviderUnknown = 0x800b0001,           // Trust provider is not recognized on this system
            //ActionUnknown = 0x800b0002,         // Trust provider does not support the specified action
            //SubjectFormUnknown = 0x800b0003,        // Trust provider does not support the form specified for the subject
            //SubjectNotTrusted = 0x800b0004,         // Subject failed the specified verification action
            //FileNotSigned = 0x800B0100,         // TRUST_E_NOSIGNATURE - File was not signed
            //SubjectExplicitlyDistrusted = 0x800B0111,   // Signer's certificate is in the Untrusted Publishers store
            //SignatureOrFileCorrupt = 0x80096010,    // TRUST_E_BAD_DIGEST - file was probably corrupt
            //SubjectCertExpired = 0x800B0101,        // CERT_E_EXPIRED - Signer's certificate was expired
            //SubjectCertificateRevoked = 0x800B010C,     // CERT_E_REVOKED Subject's certificate was revoked
            //UntrustedRoot = 0x800B0109          // CERT_E_UNTRUSTEDROOT - A certification chain processed correctly but terminated in a root certificate that is not trusted by the trust provider.
            ERROR_AUDITING_DISABLED = 0xC0090001,
            ERROR_ALL_SIDS_FILTERED = 0xC0090002,
            ERROR_BIZRULES_NOT_ENABLED = 0xC0090003,
            APPX_E_PACKAGING_INTERNAL = 0x80080200,
            APPX_E_INTERLEAVING_NOT_ALLOWED = 0x80080201,
            APPX_E_RELATIONSHIPS_NOT_ALLOWED = 0x80080202,
            APPX_E_MISSING_REQUIRED_FILE = 0x80080203,
            APPX_E_INVALID_MANIFEST = 0x80080204,
            APPX_E_INVALID_BLOCKMAP = 0x80080205,
            APPX_E_CORRUPT_CONTENT = 0x80080206,
            APPX_E_BLOCK_HASH_INVALID = 0x80080207,
            APPX_E_REQUESTED_RANGE_TOO_LARGE = 0x80080208,
            APPX_E_INVALID_SIP_CLIENT_DATA = 0x80080209,
            E_APPLICATION_ACTIVATION_TIMED_OUT = 0x8027025A,
            E_APPLICATION_ACTIVATION_EXEC_FAILURE = 0x8027025B,
            E_APPLICATION_TEMPORARY_LICENSE_ERROR = 0x8027025C,
            NTE_BAD_UID = 0x80090001,
            NTE_BAD_HASH = 0x80090002,
            NTE_BAD_KEY = 0x80090003,
            NTE_BAD_LEN = 0x80090004,
            NTE_BAD_DATA = 0x80090005,
            NTE_BAD_SIGNATURE = 0x80090006,
            NTE_BAD_VER = 0x80090007,
            NTE_BAD_ALGID = 0x80090008,
            NTE_BAD_FLAGS = 0x80090009,
            NTE_BAD_TYPE = 0x8009000A,
            NTE_BAD_KEY_STATE = 0x8009000B,
            NTE_BAD_HASH_STATE = 0x8009000C,
            NTE_NO_KEY = 0x8009000D,
            NTE_NO_MEMORY = 0x8009000E,
            NTE_EXISTS = 0x8009000F,
            NTE_PERM = 0x80090010,
            NTE_NOT_FOUND = 0x80090011,
            NTE_DOUBLE_ENCRYPT = 0x80090012,
            NTE_BAD_PROVIDER = 0x80090013,
            NTE_BAD_PROV_TYPE = 0x80090014,
            NTE_BAD_PUBLIC_KEY = 0x80090015,
            NTE_BAD_KEYSET = 0x80090016,
            NTE_PROV_TYPE_NOT_DEF = 0x80090017,
            NTE_PROV_TYPE_ENTRY_BAD = 0x80090018,
            NTE_KEYSET_NOT_DEF = 0x80090019,
            NTE_KEYSET_ENTRY_BAD = 0x8009001A,
            NTE_PROV_TYPE_NO_MATCH = 0x8009001B,
            NTE_SIGNATURE_FILE_BAD = 0x8009001C,
            NTE_PROVIDER_DLL_FAIL = 0x8009001D,
            NTE_PROV_DLL_NOT_FOUND = 0x8009001E,
            NTE_BAD_KEYSET_PARAM = 0x8009001F,
            NTE_FAIL = 0x80090020,
            NTE_SYS_ERR = 0x80090021,
            NTE_SILENT_CONTEXT = 0x80090022,
            NTE_TOKEN_KEYSET_STORAGE_FULL = 0x80090023,
            NTE_TEMPORARY_PROFILE = 0x80090024,
            NTE_FIXEDPARAMETER = 0x80090025,
            NTE_INVALID_HANDLE = 0x80090026,
            NTE_INVALID_PARAMETER = 0x80090027,
            NTE_BUFFER_TOO_SMALL = 0x80090028,
            NTE_NOT_SUPPORTED = 0x80090029,
            NTE_NO_MORE_ITEMS = 0x8009002A,
            NTE_BUFFERS_OVERLAP = 0x8009002B,
            NTE_DECRYPTION_FAILURE = 0x8009002C,
            NTE_INTERNAL_ERROR = 0x8009002D,
            NTE_UI_REQUIRED = 0x8009002E,
            NTE_HMAC_NOT_SUPPORTED = 0x8009002F,
            NTE_DEVICE_NOT_READY = 0x80090030,
            NTE_AUTHENTICATION_IGNORED = 0x80090031,
            NTE_VALIDATION_FAILED = 0x80090032,
            NTE_INCORRECT_PASSWORD = 0x80090033,
            NTE_ENCRYPTION_FAILURE = 0x80090034,
            SEC_E_INSUFFICIENT_MEMORY = 0x80090300,
            SEC_E_INVALID_HANDLE = 0x80090301,
            SEC_E_UNSUPPORTED_FUNCTION = 0x80090302,
            SEC_E_TARGET_UNKNOWN = 0x80090303,
            SEC_E_INTERNAL_ERROR = 0x80090304,
            SEC_E_SECPKG_NOT_FOUND = 0x80090305,
            SEC_E_NOT_OWNER = 0x80090306,
            SEC_E_CANNOT_INSTALL = 0x80090307,
            SEC_E_INVALID_TOKEN = 0x80090308,
            SEC_E_CANNOT_PACK = 0x80090309,
            SEC_E_QOP_NOT_SUPPORTED = 0x8009030A,
            SEC_E_NO_IMPERSONATION = 0x8009030B,
            SEC_E_LOGON_DENIED = 0x8009030C,
            SEC_E_UNKNOWN_CREDENTIALS = 0x8009030D,
            SEC_E_NO_CREDENTIALS = 0x8009030E,
            SEC_E_MESSAGE_ALTERED = 0x8009030F,
            SEC_E_OUT_OF_SEQUENCE = 0x80090310,
            SEC_E_NO_AUTHENTICATING_AUTHORITY = 0x80090311,
            SEC_I_CONTINUE_NEEDED = 0x00090312,
            SEC_I_COMPLETE_NEEDED = 0x00090313,
            SEC_I_COMPLETE_AND_CONTINUE = 0x00090314,
            SEC_I_LOCAL_LOGON = 0x00090315,
            SEC_E_BAD_PKGID = 0x80090316,
            SEC_E_CONTEXT_EXPIRED = 0x80090317,
            SEC_I_CONTEXT_EXPIRED = 0x00090317,
            SEC_E_INCOMPLETE_MESSAGE = 0x80090318,
            SEC_E_INCOMPLETE_CREDENTIALS = 0x80090320,
            SEC_E_BUFFER_TOO_SMALL = 0x80090321,
            SEC_I_INCOMPLETE_CREDENTIALS = 0x00090320,
            SEC_I_RENEGOTIATE = 0x00090321,
            SEC_E_WRONG_PRINCIPAL = 0x80090322,
            SEC_I_NO_LSA_CONTEXT = 0x00090323,
            SEC_E_TIME_SKEW = 0x80090324,
            SEC_E_UNTRUSTED_ROOT = 0x80090325,
            SEC_E_ILLEGAL_MESSAGE = 0x80090326,
            SEC_E_CERT_UNKNOWN = 0x80090327,
            SEC_E_CERT_EXPIRED = 0x80090328,
            SEC_E_ENCRYPT_FAILURE = 0x80090329,
            SEC_E_DECRYPT_FAILURE = 0x80090330,
            SEC_E_ALGORITHM_MISMATCH = 0x80090331,
            SEC_E_SECURITY_QOS_FAILED = 0x80090332,
            SEC_E_UNFINISHED_CONTEXT_DELETED = 0x80090333,
            SEC_E_NO_TGT_REPLY = 0x80090334,
            SEC_E_NO_IP_ADDRESSES = 0x80090335,
            SEC_E_WRONG_CREDENTIAL_HANDLE = 0x80090336,
            SEC_E_CRYPTO_SYSTEM_INVALID = 0x80090337,
            SEC_E_MAX_REFERRALS_EXCEEDED = 0x80090338,
            SEC_E_MUST_BE_KDC = 0x80090339,
            SEC_E_STRONG_CRYPTO_NOT_SUPPORTED = 0x8009033A,
            SEC_E_TOO_MANY_PRINCIPALS = 0x8009033B,
            SEC_E_NO_PA_DATA = 0x8009033C,
            SEC_E_PKINIT_NAME_MISMATCH = 0x8009033D,
            SEC_E_SMARTCARD_LOGON_REQUIRED = 0x8009033E,
            SEC_E_SHUTDOWN_IN_PROGRESS = 0x8009033F,
            SEC_E_KDC_INVALID_REQUEST = 0x80090340,
            SEC_E_KDC_UNABLE_TO_REFER = 0x80090341,
            SEC_E_KDC_UNKNOWN_ETYPE = 0x80090342,
            SEC_E_UNSUPPORTED_PREAUTH = 0x80090343,
            SEC_E_DELEGATION_REQUIRED = 0x80090345,
            SEC_E_BAD_BINDINGS = 0x80090346,
            SEC_E_MULTIPLE_ACCOUNTS = 0x80090347,
            SEC_E_NO_KERB_KEY = 0x80090348,
            SEC_E_CERT_WRONG_USAGE = 0x80090349,
            SEC_E_DOWNGRADE_DETECTED = 0x80090350,
            SEC_E_SMARTCARD_CERT_REVOKED = 0x80090351,
            SEC_E_ISSUING_CA_UNTRUSTED = 0x80090352,
            SEC_E_REVOCATION_OFFLINE_C = 0x80090353,
            SEC_E_PKINIT_CLIENT_FAILURE = 0x80090354,
            SEC_E_SMARTCARD_CERT_EXPIRED = 0x80090355,
            SEC_E_NO_S4U_PROT_SUPPORT = 0x80090356,
            SEC_E_CROSSREALM_DELEGATION_FAILURE = 0x80090357,
            SEC_E_REVOCATION_OFFLINE_KDC = 0x80090358,
            SEC_E_ISSUING_CA_UNTRUSTED_KDC = 0x80090359,
            SEC_E_KDC_CERT_EXPIRED = 0x8009035A,
            SEC_E_KDC_CERT_REVOKED = 0x8009035B,
            SEC_I_SIGNATURE_NEEDED = 0x0009035C,
            SEC_E_INVALID_PARAMETER = 0x8009035D,
            SEC_E_DELEGATION_POLICY = 0x8009035E,
            SEC_E_POLICY_NLTM_ONLY = 0x8009035F,
            SEC_I_NO_RENEGOTIATION = 0x00090360,
            SEC_E_NO_CONTEXT = 0x80090361,
            SEC_E_PKU2U_CERT_FAILURE = 0x80090362,
            SEC_E_MUTUAL_AUTH_FAILED = 0x80090363,
            SEC_I_MESSAGE_FRAGMENT = 0x00090364,
            SEC_E_ONLY_HTTPS_ALLOWED = 0x80090365,
            SEC_I_CONTINUE_NEEDED_MESSAGE_OK = 0x80090366,
            CRYPT_E_MSG_ERROR = 0x80091001,
            CRYPT_E_UNKNOWN_ALGO = 0x80091002,
            CRYPT_E_OID_FORMAT = 0x80091003,
            CRYPT_E_INVALID_MSG_TYPE = 0x80091004,
            CRYPT_E_UNEXPECTED_ENCODING = 0x80091005,
            CRYPT_E_AUTH_ATTR_MISSING = 0x80091006,
            CRYPT_E_HASH_VALUE = 0x80091007,
            CRYPT_E_INVALID_INDEX = 0x80091008,
            CRYPT_E_ALREADY_DECRYPTED = 0x80091009,
            CRYPT_E_NOT_DECRYPTED = 0x8009100A,
            CRYPT_E_RECIPIENT_NOT_FOUND = 0x8009100B,
            CRYPT_E_CONTROL_TYPE = 0x8009100C,
            CRYPT_E_ISSUER_SERIALNUMBER = 0x8009100D,
            CRYPT_E_SIGNER_NOT_FOUND = 0x8009100E,
            CRYPT_E_ATTRIBUTES_MISSING = 0x8009100F,
            CRYPT_E_STREAM_MSG_NOT_READY = 0x80091010,
            CRYPT_E_STREAM_INSUFFICIENT_DATA = 0x80091011,
            CRYPT_I_NEW_PROTECTION_REQUIRED = 0x00091012,
            CRYPT_E_BAD_LEN = 0x80092001,
            CRYPT_E_BAD_ENCODE = 0x80092002,
            CRYPT_E_FILE_ERROR = 0x80092003,
            CRYPT_E_NOT_FOUND = 0x80092004,
            CRYPT_E_EXISTS = 0x80092005,
            CRYPT_E_NO_PROVIDER = 0x80092006,
            CRYPT_E_SELF_SIGNED = 0x80092007,
            CRYPT_E_DELETED_PREV = 0x80092008,
            CRYPT_E_NO_MATCH = 0x80092009,
            CRYPT_E_UNEXPECTED_MSG_TYPE = 0x8009200A,
            CRYPT_E_NO_KEY_PROPERTY = 0x8009200B,
            CRYPT_E_NO_DECRYPT_CERT = 0x8009200C,
            CRYPT_E_BAD_MSG = 0x8009200D,
            CRYPT_E_NO_SIGNER = 0x8009200E,
            CRYPT_E_PENDING_CLOSE = 0x8009200F,
            CRYPT_E_REVOKED = 0x80092010,
            CRYPT_E_NO_REVOCATION_DLL = 0x80092011,
            CRYPT_E_NO_REVOCATION_CHECK = 0x80092012,
            CRYPT_E_REVOCATION_OFFLINE = 0x80092013,
            CRYPT_E_NOT_IN_REVOCATION_DATABASE = 0x80092014,
            CRYPT_E_INVALID_NUMERIC_STRING = 0x80092020,
            CRYPT_E_INVALID_PRINTABLE_STRING = 0x80092021,
            CRYPT_E_INVALID_IA5_STRING = 0x80092022,
            CRYPT_E_INVALID_X500_STRING = 0x80092023,
            CRYPT_E_NOT_CHAR_STRING = 0x80092024,
            CRYPT_E_FILERESIZED = 0x80092025,
            CRYPT_E_SECURITY_SETTINGS = 0x80092026,
            CRYPT_E_NO_VERIFY_USAGE_DLL = 0x80092027,
            CRYPT_E_NO_VERIFY_USAGE_CHECK = 0x80092028,
            CRYPT_E_VERIFY_USAGE_OFFLINE = 0x80092029,
            CRYPT_E_NOT_IN_CTL = 0x8009202A,
            CRYPT_E_NO_TRUSTED_SIGNER = 0x8009202B,
            CRYPT_E_MISSING_PUBKEY_PARA = 0x8009202C,
            CRYPT_E_OBJECT_LOCATOR_NOT_FOUND = 0x8009202d,
            CRYPT_E_OSS_ERROR = 0x80093000,
            OSS_MORE_BUF = 0x80093001,
            OSS_NEGATIVE_UINTEGER = 0x80093002,
            OSS_PDU_RANGE = 0x80093003,
            OSS_MORE_INPUT = 0x80093004,
            OSS_DATA_ERROR = 0x80093005,
            OSS_BAD_ARG = 0x80093006,
            OSS_BAD_VERSION = 0x80093007,
            OSS_OUT_MEMORY = 0x80093008,
            OSS_PDU_MISMATCH = 0x80093009,
            OSS_LIMITED = 0x8009300A,
            OSS_BAD_PTR = 0x8009300B,
            OSS_BAD_TIME = 0x8009300C,
            OSS_INDEFINITE_NOT_SUPPORTED = 0x8009300D,
            OSS_MEM_ERROR = 0x8009300E,
            OSS_BAD_TABLE = 0x8009300F,
            OSS_TOO_LONG = 0x80093010,
            OSS_CONSTRAINT_VIOLATED = 0x80093011,
            OSS_FATAL_ERROR = 0x80093012,
            OSS_ACCESS_SERIALIZATION_ERROR = 0x80093013,
            OSS_NULL_TBL = 0x80093014,
            OSS_NULL_FCN = 0x80093015,
            OSS_BAD_ENCRULES = 0x80093016,
            OSS_UNAVAIL_ENCRULES = 0x80093017,
            OSS_CANT_OPEN_TRACE_WINDOW = 0x80093018,
            OSS_UNIMPLEMENTED = 0x80093019,
            OSS_OID_DLL_NOT_LINKED = 0x8009301A,
            OSS_CANT_OPEN_TRACE_FILE = 0x8009301B,
            OSS_TRACE_FILE_ALREADY_OPEN = 0x8009301C,
            OSS_TABLE_MISMATCH = 0x8009301D,
            OSS_TYPE_NOT_SUPPORTED = 0x8009301E,
            OSS_REAL_DLL_NOT_LINKED = 0x8009301F,
            OSS_REAL_CODE_NOT_LINKED = 0x80093020,
            OSS_OUT_OF_RANGE = 0x80093021,
            OSS_COPIER_DLL_NOT_LINKED = 0x80093022,
            OSS_CONSTRAINT_DLL_NOT_LINKED = 0x80093023,
            OSS_COMPARATOR_DLL_NOT_LINKED = 0x80093024,
            OSS_COMPARATOR_CODE_NOT_LINKED = 0x80093025,
            OSS_MEM_MGR_DLL_NOT_LINKED = 0x80093026,
            OSS_PDV_DLL_NOT_LINKED = 0x80093027,
            OSS_PDV_CODE_NOT_LINKED = 0x80093028,
            OSS_API_DLL_NOT_LINKED = 0x80093029,
            OSS_BERDER_DLL_NOT_LINKED = 0x8009302A,
            OSS_PER_DLL_NOT_LINKED = 0x8009302B,
            OSS_OPEN_TYPE_ERROR = 0x8009302C,
            OSS_MUTEX_NOT_CREATED = 0x8009302D,
            OSS_CANT_CLOSE_TRACE_FILE = 0x8009302E,
            CRYPT_E_ASN1_ERROR = 0x80093100,
            CRYPT_E_ASN1_INTERNAL = 0x80093101,
            CRYPT_E_ASN1_EOD = 0x80093102,
            CRYPT_E_ASN1_CORRUPT = 0x80093103,
            CRYPT_E_ASN1_LARGE = 0x80093104,
            CRYPT_E_ASN1_CONSTRAINT = 0x80093105,
            CRYPT_E_ASN1_MEMORY = 0x80093106,
            CRYPT_E_ASN1_OVERFLOW = 0x80093107,
            CRYPT_E_ASN1_BADPDU = 0x80093108,
            CRYPT_E_ASN1_BADARGS = 0x80093109,
            CRYPT_E_ASN1_BADREAL = 0x8009310A,
            CRYPT_E_ASN1_BADTAG = 0x8009310B,
            CRYPT_E_ASN1_CHOICE = 0x8009310C,
            CRYPT_E_ASN1_RULE = 0x8009310D,
            CRYPT_E_ASN1_UTF8 = 0x8009310E,
            CRYPT_E_ASN1_PDU_TYPE = 0x80093133,
            CRYPT_E_ASN1_NYI = 0x80093134,
            CRYPT_E_ASN1_EXTENDED = 0x80093201,
            CRYPT_E_ASN1_NOEOD = 0x80093202,
            CERTSRV_E_BAD_REQUESTSUBJECT = 0x80094001,
            CERTSRV_E_NO_REQUEST = 0x80094002,
            CERTSRV_E_BAD_REQUESTSTATUS = 0x80094003,
            CERTSRV_E_PROPERTY_EMPTY = 0x80094004,
            CERTSRV_E_INVALID_CA_CERTIFICATE = 0x80094005,
            CERTSRV_E_SERVER_SUSPENDED = 0x80094006,
            CERTSRV_E_ENCODING_LENGTH = 0x80094007,
            CERTSRV_E_ROLECONFLICT = 0x80094008,
            CERTSRV_E_RESTRICTEDOFFICER = 0x80094009,
            CERTSRV_E_KEY_ARCHIVAL_NOT_CONFIGURED = 0x8009400A,
            CERTSRV_E_NO_VALID_KRA = 0x8009400B,
            CERTSRV_E_BAD_REQUEST_KEY_ARCHIVAL = 0x8009400C,
            CERTSRV_E_NO_CAADMIN_DEFINED = 0x8009400D,
            CERTSRV_E_BAD_RENEWAL_CERT_ATTRIBUTE = 0x8009400E,
            CERTSRV_E_NO_DB_SESSIONS = 0x8009400F,
            CERTSRV_E_ALIGNMENT_FAULT = 0x80094010,
            CERTSRV_E_ENROLL_DENIED = 0x80094011,
            CERTSRV_E_TEMPLATE_DENIED = 0x80094012,
            CERTSRV_E_DOWNLEVEL_DC_SSL_OR_UPGRADE = 0x80094013,
            CERTSRV_E_ADMIN_DENIED_REQUEST = 0x80094014,
            CERTSRV_E_NO_POLICY_SERVER = 0x80094015,
            CERTSRV_E_UNSUPPORTED_CERT_TYPE = 0x80094800,
            CERTSRV_E_NO_CERT_TYPE = 0x80094801,
            CERTSRV_E_TEMPLATE_CONFLICT = 0x80094802,
            CERTSRV_E_SUBJECT_ALT_NAME_REQUIRED = 0x80094803,
            CERTSRV_E_ARCHIVED_KEY_REQUIRED = 0x80094804,
            CERTSRV_E_SMIME_REQUIRED = 0x80094805,
            CERTSRV_E_BAD_RENEWAL_SUBJECT = 0x80094806,
            CERTSRV_E_BAD_TEMPLATE_VERSION = 0x80094807,
            CERTSRV_E_TEMPLATE_POLICY_REQUIRED = 0x80094808,
            CERTSRV_E_SIGNATURE_POLICY_REQUIRED = 0x80094809,
            CERTSRV_E_SIGNATURE_COUNT = 0x8009480A,
            CERTSRV_E_SIGNATURE_REJECTED = 0x8009480B,
            CERTSRV_E_ISSUANCE_POLICY_REQUIRED = 0x8009480C,
            CERTSRV_E_SUBJECT_UPN_REQUIRED = 0x8009480D,
            CERTSRV_E_SUBJECT_DIRECTORY_GUID_REQUIRED = 0x8009480E,
            CERTSRV_E_SUBJECT_DNS_REQUIRED = 0x8009480F,
            CERTSRV_E_ARCHIVED_KEY_UNEXPECTED = 0x80094810,
            CERTSRV_E_KEY_LENGTH = 0x80094811,
            CERTSRV_E_SUBJECT_EMAIL_REQUIRED = 0x80094812,
            CERTSRV_E_UNKNOWN_CERT_TYPE = 0x80094813,
            CERTSRV_E_CERT_TYPE_OVERLAP = 0x80094814,
            CERTSRV_E_TOO_MANY_SIGNATURES = 0x80094815,
            CERTSRV_E_RENEWAL_BAD_PUBLIC_KEY = 0x80094816,
            XENROLL_E_KEY_NOT_EXPORTABLE = 0x80095000,
            XENROLL_E_CANNOT_ADD_ROOT_CERT = 0x80095001,
            XENROLL_E_RESPONSE_KA_HASH_NOT_FOUND = 0x80095002,
            XENROLL_E_RESPONSE_UNEXPECTED_KA_HASH = 0x80095003,
            XENROLL_E_RESPONSE_KA_HASH_MISMATCH = 0x80095004,
            XENROLL_E_KEYSPEC_SMIME_MISMATCH = 0x80095005,
            TRUST_E_SYSTEM_ERROR = 0x80096001,
            TRUST_E_NO_SIGNER_CERT = 0x80096002,
            TRUST_E_COUNTER_SIGNER = 0x80096003,
            TRUST_E_CERT_SIGNATURE = 0x80096004,
            TRUST_E_TIME_STAMP = 0x80096005,
            TRUST_E_BAD_DIGEST = 0x80096010,
            TRUST_E_BASIC_CONSTRAINTS = 0x80096019,
            TRUST_E_FINANCIAL_CRITERIA = 0x8009601E,
            MSSIPOTF_E_OUTOFMEMRANGE = 0x80097001,
            MSSIPOTF_E_CANTGETOBJECT = 0x80097002,
            MSSIPOTF_E_NOHEADTABLE = 0x80097003,
            MSSIPOTF_E_BAD_MAGICNUMBER = 0x80097004,
            MSSIPOTF_E_BAD_OFFSET_TABLE = 0x80097005,
            MSSIPOTF_E_TABLE_TAGORDER = 0x80097006,
            MSSIPOTF_E_TABLE_LONGWORD = 0x80097007,
            MSSIPOTF_E_BAD_FIRST_TABLE_PLACEMENT = 0x80097008,
            MSSIPOTF_E_TABLES_OVERLAP = 0x80097009,
            MSSIPOTF_E_TABLE_PADBYTES = 0x8009700A,
            MSSIPOTF_E_FILETOOSMALL = 0x8009700B,
            MSSIPOTF_E_TABLE_CHECKSUM = 0x8009700C,
            MSSIPOTF_E_FILE_CHECKSUM = 0x8009700D,
            MSSIPOTF_E_FAILED_POLICY = 0x80097010,
            MSSIPOTF_E_FAILED_HINTS_CHECK = 0x80097011,
            MSSIPOTF_E_NOT_OPENTYPE = 0x80097012,
            MSSIPOTF_E_FILE = 0x80097013,
            MSSIPOTF_E_CRYPT = 0x80097014,
            MSSIPOTF_E_BADVERSION = 0x80097015,
            MSSIPOTF_E_DSIG_STRUCTURE = 0x80097016,
            MSSIPOTF_E_PCONST_CHECK = 0x80097017,
            MSSIPOTF_E_STRUCTURE = 0x80097018,
            ERROR_CRED_REQUIRES_CONFIRMATION = 0x80097019,
            TRUST_E_PROVIDER_UNKNOWN = 0x800B0001,
            TRUST_E_ACTION_UNKNOWN = 0x800B0002,
            TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0003,
            TRUST_E_SUBJECT_NOT_TRUSTED = 0x800B0004,
            DIGSIG_E_ENCODE = 0x800B0005,
            DIGSIG_E_DECODE = 0x800B0006,
            DIGSIG_E_EXTENSIBILITY = 0x800B0007,
            DIGSIG_E_CRYPTO = 0x800B0008,
            PERSIST_E_SIZEDEFINITE = 0x800B0009,
            PERSIST_E_SIZEINDEFINITE = 0x800B000A,
            PERSIST_E_NOTSELFSIZING = 0x800B000B,
            TRUST_E_NOSIGNATURE = 0x800B0100,
            CERT_E_EXPIRED = 0x800B0101,
            CERT_E_VALIDITYPERIODNESTING = 0x800B0102,
            CERT_E_ROLE = 0x800B0103,
            CERT_E_PATHLENCONST = 0x800B0104,
            CERT_E_CRITICAL = 0x800B0105,
            CERT_E_PURPOSE = 0x800B0106,
            CERT_E_ISSUERCHAINING = 0x800B0107,
            CERT_E_MALFORMED = 0x800B0108,
            CERT_E_UNTRUSTEDROOT = 0x800B0109,
            CERT_E_CHAINING = 0x800B010A,
            TRUST_E_FAIL = 0x800B010B,
            CERT_E_REVOKED = 0x800B010C,
            CERT_E_UNTRUSTEDTESTROOT = 0x800B010D,
            CERT_E_REVOCATION_FAILURE = 0x800B010E,
            CERT_E_CN_NO_MATCH = 0x800B010F,
            CERT_E_WRONG_USAGE = 0x800B0110,
            TRUST_E_EXPLICIT_DISTRUST = 0x800B0111,
            CERT_E_UNTRUSTEDCA = 0x800B0112,
            CERT_E_INVALID_POLICY = 0x800B0113,
            CERT_E_INVALID_NAME = 0x800B0114,
            SPAPI_E_EXPECTED_SECTION_NAME = 0x800F0000,
            SPAPI_E_BAD_SECTION_NAME_LINE = 0x800F0001,
            SPAPI_E_SECTION_NAME_TOO_LONG = 0x800F0002,
            SPAPI_E_GENERAL_SYNTAX = 0x800F0003,
            SPAPI_E_WRONG_INF_STYLE = 0x800F0100,
            SPAPI_E_SECTION_NOT_FOUND = 0x800F0101,
            SPAPI_E_LINE_NOT_FOUND = 0x800F0102,
            SPAPI_E_NO_BACKUP = 0x800F0103,
            SPAPI_E_NO_ASSOCIATED_CLASS = 0x800F0200,
            SPAPI_E_CLASS_MISMATCH = 0x800F0201,
            SPAPI_E_DUPLICATE_FOUND = 0x800F0202,
            SPAPI_E_NO_DRIVER_SELECTED = 0x800F0203,
            SPAPI_E_KEY_DOES_NOT_EXIST = 0x800F0204,
            SPAPI_E_INVALID_DEVINST_NAME = 0x800F0205,
            SPAPI_E_INVALID_CLASS = 0x800F0206,
            SPAPI_E_DEVINST_ALREADY_EXISTS = 0x800F0207,
            SPAPI_E_DEVINFO_NOT_REGISTERED = 0x800F0208,
            SPAPI_E_INVALID_REG_PROPERTY = 0x800F0209,
            SPAPI_E_NO_INF = 0x800F020A,
            SPAPI_E_NO_SUCH_DEVINST = 0x800F020B,
            SPAPI_E_CANT_LOAD_CLASS_ICON = 0x800F020C,
            SPAPI_E_INVALID_CLASS_INSTALLER = 0x800F020D,
            SPAPI_E_DI_DO_DEFAULT = 0x800F020E,
            SPAPI_E_DI_NOFILECOPY = 0x800F020F,
            SPAPI_E_INVALID_HWPROFILE = 0x800F0210,
            SPAPI_E_NO_DEVICE_SELECTED = 0x800F0211,
            SPAPI_E_DEVINFO_LIST_LOCKED = 0x800F0212,
            SPAPI_E_DEVINFO_DATA_LOCKED = 0x800F0213,
            SPAPI_E_DI_BAD_PATH = 0x800F0214,
            SPAPI_E_NO_CLASSINSTALL_PARAMS = 0x800F0215,
            SPAPI_E_FILEQUEUE_LOCKED = 0x800F0216,
            SPAPI_E_BAD_SERVICE_INSTALLSECT = 0x800F0217,
            SPAPI_E_NO_CLASS_DRIVER_LIST = 0x800F0218,
            SPAPI_E_NO_ASSOCIATED_SERVICE = 0x800F0219,
            SPAPI_E_NO_DEFAULT_DEVICE_INTERFACE = 0x800F021A,
            SPAPI_E_DEVICE_INTERFACE_ACTIVE = 0x800F021B,
            SPAPI_E_DEVICE_INTERFACE_REMOVED = 0x800F021C,
            SPAPI_E_BAD_INTERFACE_INSTALLSECT = 0x800F021D,
            SPAPI_E_NO_SUCH_INTERFACE_CLASS = 0x800F021E,
            SPAPI_E_INVALID_REFERENCE_STRING = 0x800F021F,
            SPAPI_E_INVALID_MACHINENAME = 0x800F0220,
            SPAPI_E_REMOTE_COMM_FAILURE = 0x800F0221,
            SPAPI_E_MACHINE_UNAVAILABLE = 0x800F0222,
            SPAPI_E_NO_CONFIGMGR_SERVICES = 0x800F0223,
            SPAPI_E_INVALID_PROPPAGE_PROVIDER = 0x800F0224,
            SPAPI_E_NO_SUCH_DEVICE_INTERFACE = 0x800F0225,
            SPAPI_E_DI_POSTPROCESSING_REQUIRED = 0x800F0226,
            SPAPI_E_INVALID_COINSTALLER = 0x800F0227,
            SPAPI_E_NO_COMPAT_DRIVERS = 0x800F0228,
            SPAPI_E_NO_DEVICE_ICON = 0x800F0229,
            SPAPI_E_INVALID_INF_LOGCONFIG = 0x800F022A,
            SPAPI_E_DI_DONT_INSTALL = 0x800F022B,
            SPAPI_E_INVALID_FILTER_DRIVER = 0x800F022C,
            SPAPI_E_NON_WINDOWS_NT_DRIVER = 0x800F022D,
            SPAPI_E_NON_WINDOWS_DRIVER = 0x800F022E,
            SPAPI_E_NO_CATALOG_FOR_OEM_INF = 0x800F022F,
            SPAPI_E_DEVINSTALL_QUEUE_NONNATIVE = 0x800F0230,
            SPAPI_E_NOT_DISABLEABLE = 0x800F0231,
            SPAPI_E_CANT_REMOVE_DEVINST = 0x800F0232,
            SPAPI_E_INVALID_TARGET = 0x800F0233,
            SPAPI_E_DRIVER_NONNATIVE = 0x800F0234,
            SPAPI_E_IN_WOW64 = 0x800F0235,
            SPAPI_E_SET_SYSTEM_RESTORE_POINT = 0x800F0236,
            SPAPI_E_INCORRECTLY_COPIED_INF = 0x800F0237,
            SPAPI_E_SCE_DISABLED = 0x800F0238,
            SPAPI_E_UNKNOWN_EXCEPTION = 0x800F0239,
            SPAPI_E_PNP_REGISTRY_ERROR = 0x800F023A,
            SPAPI_E_REMOTE_REQUEST_UNSUPPORTED = 0x800F023B,
            SPAPI_E_NOT_AN_INSTALLED_OEM_INF = 0x800F023C,
            SPAPI_E_INF_IN_USE_BY_DEVICES = 0x800F023D,
            SPAPI_E_DI_FUNCTION_OBSOLETE = 0x800F023E,
            SPAPI_E_NO_AUTHENTICODE_CATALOG = 0x800F023F,
            SPAPI_E_AUTHENTICODE_DISALLOWED = 0x800F0240,
            SPAPI_E_AUTHENTICODE_TRUSTED_PUBLISHER = 0x800F0241,
            SPAPI_E_AUTHENTICODE_TRUST_NOT_ESTABLISHED = 0x800F0242,
            SPAPI_E_AUTHENTICODE_PUBLISHER_NOT_TRUSTED = 0x800F0243,
            SPAPI_E_SIGNATURE_OSATTRIBUTE_MISMATCH = 0x800F0244,
            SPAPI_E_ONLY_VALIDATE_VIA_AUTHENTICODE = 0x800F0245,
            SPAPI_E_DEVICE_INSTALLER_NOT_READY = 0x800F0246,
            SPAPI_E_DRIVER_STORE_ADD_FAILED = 0x800F0247,
            SPAPI_E_DEVICE_INSTALL_BLOCKED = 0x800F0248,
            SPAPI_E_DRIVER_INSTALL_BLOCKED = 0x800F0249,
            SPAPI_E_WRONG_INF_TYPE = 0x800F024A,
            SPAPI_E_FILE_HASH_NOT_IN_CATALOG = 0x800F024B,
            SPAPI_E_DRIVER_STORE_DELETE_FAILED = 0x800F024C,
            SPAPI_E_UNRECOVERABLE_STACK_OVERFLOW = 0x800F0300,
            SPAPI_E_ERROR_NOT_INSTALLED = 0x800F1000,
            SCARD_F_INTERNAL_ERROR = 0x80100001,
            SCARD_E_CANCELLED = 0x80100002,
            SCARD_E_INVALID_HANDLE = 0x80100003,
            SCARD_E_INVALID_PARAMETER = 0x80100004,
            SCARD_E_INVALID_TARGET = 0x80100005,
            SCARD_E_NO_MEMORY = 0x80100006,
            SCARD_F_WAITED_TOO_LONG = 0x80100007,
            SCARD_E_INSUFFICIENT_BUFFER = 0x80100008,
            SCARD_E_UNKNOWN_READER = 0x80100009,
            SCARD_E_TIMEOUT = 0x8010000A,
            SCARD_E_SHARING_VIOLATION = 0x8010000B,
            SCARD_E_NO_SMARTCARD = 0x8010000C,
            SCARD_E_UNKNOWN_CARD = 0x8010000D,
            SCARD_E_CANT_DISPOSE = 0x8010000E,
            SCARD_E_PROTO_MISMATCH = 0x8010000F,
            SCARD_E_NOT_READY = 0x80100010,
            SCARD_E_INVALID_VALUE = 0x80100011,
            SCARD_E_SYSTEM_CANCELLED = 0x80100012,
            SCARD_F_COMM_ERROR = 0x80100013,
            SCARD_F_UNKNOWN_ERROR = 0x80100014,
            SCARD_E_INVALID_ATR = 0x80100015,
            SCARD_E_NOT_TRANSACTED = 0x80100016,
            SCARD_E_READER_UNAVAILABLE = 0x80100017,
            SCARD_P_SHUTDOWN = 0x80100018,
            SCARD_E_PCI_TOO_SMALL = 0x80100019,
            SCARD_E_READER_UNSUPPORTED = 0x8010001A,
            SCARD_E_DUPLICATE_READER = 0x8010001B,
            SCARD_E_CARD_UNSUPPORTED = 0x8010001C,
            SCARD_E_NO_SERVICE = 0x8010001D,
            SCARD_E_SERVICE_STOPPED = 0x8010001E,
            SCARD_E_UNEXPECTED = 0x8010001F,
            SCARD_E_ICC_INSTALLATION = 0x80100020,
            SCARD_E_ICC_CREATEORDER = 0x80100021,
            SCARD_E_UNSUPPORTED_FEATURE = 0x80100022,
            SCARD_E_DIR_NOT_FOUND = 0x80100023,
            SCARD_E_FILE_NOT_FOUND = 0x80100024,
            SCARD_E_NO_DIR = 0x80100025,
            SCARD_E_NO_FILE = 0x80100026,
            SCARD_E_NO_ACCESS = 0x80100027,
            SCARD_E_WRITE_TOO_MANY = 0x80100028,
            SCARD_E_BAD_SEEK = 0x80100029,
            SCARD_E_INVALID_CHV = 0x8010002A,
            SCARD_E_UNKNOWN_RES_MNG = 0x8010002B,
            SCARD_E_NO_SUCH_CERTIFICATE = 0x8010002C,
            SCARD_E_CERTIFICATE_UNAVAILABLE = 0x8010002D,
            SCARD_E_NO_READERS_AVAILABLE = 0x8010002E,
            SCARD_E_COMM_DATA_LOST = 0x8010002F,
            SCARD_E_NO_KEY_CONTAINER = 0x80100030,
            SCARD_E_SERVER_TOO_BUSY = 0x80100031,
            SCARD_E_PIN_CACHE_EXPIRED = 0x80100032,
            SCARD_E_NO_PIN_CACHE = 0x80100033,
            SCARD_E_READ_ONLY_CARD = 0x80100034,
            SCARD_W_UNSUPPORTED_CARD = 0x80100065,
            SCARD_W_UNRESPONSIVE_CARD = 0x80100066,
            SCARD_W_UNPOWERED_CARD = 0x80100067,
            SCARD_W_RESET_CARD = 0x80100068,
            SCARD_W_REMOVED_CARD = 0x80100069,
            SCARD_W_SECURITY_VIOLATION = 0x8010006A,
            SCARD_W_WRONG_CHV = 0x8010006B,
            SCARD_W_CHV_BLOCKED = 0x8010006C,
            SCARD_W_EOF = 0x8010006D,
            SCARD_W_CANCELLED_BY_USER = 0x8010006E,
            SCARD_W_CARD_NOT_AUTHENTICATED = 0x8010006F,
            SCARD_W_CACHE_ITEM_NOT_FOUND = 0x80100070,
            SCARD_W_CACHE_ITEM_STALE = 0x80100071,
            SCARD_W_CACHE_ITEM_TOO_BIG = 0x80100072,
            ONL_E_INVALID_AUTHENTICATION_TARGET = 0x8A020001,
            ONL_E_ACCESS_DENIED_BY_TOU = 0x8A020002
        }
        #endregion

        #region WinTrustDll

        [DllImport("WinTrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
        static extern WinVerifyTrustResult WinVerifyTrust([In] IntPtr hwnd, [In][MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, [In, Out] WinTrustData pWVTData);

        [DllImport("WinTrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
        static extern WinVerifyTrustResult WinVerifyTrustEx([In] IntPtr hwnd, [In][MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, [In, Out] WinTrustData pWVTData);

        [DllImport("WinTrust.dll")]
        private static extern int WinVerifyTrust(IntPtr hWind, IntPtr pgActionID, IntPtr pWVTData);

        [DllImport("WinTrust.dll")]
        private static extern IntPtr WTHelperProvDataFromStateData(IntPtr hStateData);

        [DllImport("WinTrust.dll")]
        private static extern IntPtr WTHelperGetProvSignerFromChain(IntPtr pProvData, int idxSigner, bool fCounterSigner, int idxCounterSigner);

        [DllImport("WinTrust.dll")]
        private static extern IntPtr WTHelperGetProvCertFromChain(IntPtr pSgnr, int idxCert);

        // https://learn.microsoft.com/ru-ru/windows/win32/api/wincrypt/nf-wincrypt-certnametostra
        [DllImport("crypt32.dll", SetLastError = true, EntryPoint = "CertNameToStr")]
        private static extern int CertNameToStr(int dwCertEncodingType, IntPtr pName, int dwStrType, StringBuilder psz, int csz);

        #endregion WinTrustDll

        #endregion WinVerify

        #region PRIVATE

        private static string CryptIntBlobToString(CRYPT_INTEGER_BLOB blob, int strType = CERT_SIMPLE_NAME_STR | CERT_OID_NAME_STR | CERT_NAME_STR_CRLF_FLAG | CERT_NAME_STR_NO_QUOTING_FLAG | CERT_NAME_STR_REVERSE_FLAG)
        {
            if (blob.cbData == 0 || blob.pbData == IntPtr.Zero) return null;

            IntPtr blobPtr = IntPtr.Zero;
            string result = null;
            try
            {
                blobPtr = Marshal.AllocHGlobal(blob.cbData);
                Marshal.StructureToPtr(blob, blobPtr, true);
                int len = CertNameToStr(X509_ASN_ENCODING, blobPtr, strType, null, 0);
                StringBuilder sb = new StringBuilder(len);
                CertNameToStr(X509_ASN_ENCODING, blobPtr, strType, sb, len);
                result = sb.ToString();
            }
            finally
            {
                if (blobPtr != IntPtr.Zero) Marshal.FreeHGlobal(blobPtr);
            };
            return result;
        }

        private static Oid CryptAlgorythmIdtoOid(CRYPT_ALGORITHM_IDENTIFIER ident)
        {
            try
            {
                if (ident.pszObjId != IntPtr.Zero)
                {
                    string objId = Marshal.PtrToStringAnsi(ident.pszObjId);
                    if (!string.IsNullOrEmpty(objId))
                        return Oid.FromOidValue(objId, OidGroup.All);
                };
            }
            catch { };
            return null;
        }

        #endregion PRIVATE

        public static WinVerifyTrustResult GetSignatureFileInfo(string fileName, out VERIFY_SIGNATURE[] signs, out Exception ex)
        {
            signs = null;
            ex = null;
            WinTrustFileInfo wtfi = null;
            WinTrustData wtd = null;
            List<VERIFY_SIGNATURE> signatures = new List<VERIFY_SIGNATURE>();
            try
            {
                wtfi = new WinTrustFileInfo(fileName);

                wtd = new WinTrustData(wtfi);

                WinTrustSignatureSettings ss = new WinTrustSignatureSettings();
                ss.cbStruct = Marshal.SizeOf(typeof(WinTrustSignatureSettings));
                ss.dwFlags = WSS_GET_SECONDARY_SIG_COUNT;
                wtd.pSignatureSettings = Marshal.AllocHGlobal(ss.cbStruct);
                Marshal.StructureToPtr(ss, wtd.pSignatureSettings, false);

                Guid guidAction = new Guid(WINTRUST_ACTION_GENERIC_VERIFY_V2);
                WinVerifyTrustResult result = WinVerifyTrust((IntPtr)INVALID_HANDLE_VALUE, guidAction, wtd);
                ss = (WinTrustSignatureSettings)Marshal.PtrToStructure(wtd.pSignatureSettings, typeof(WinTrustSignatureSettings));

                try
                {
                    int sigCount = ss.cSecondarySigs + 1;
                    for (int sigId = 0; sigId < sigCount; sigId++)
                    {
                        ss.dwIndex = sigId;
                        ss.dwFlags = WSS_VERIFY_SPECIFIC;
                        Marshal.StructureToPtr(ss, wtd.pSignatureSettings, false);
                        wtd.StateAction = WinTrustDataStateAction.Verify;
                        wtd.StateData = IntPtr.Zero;
                        WinVerifyTrustResult sigResult = WinVerifyTrust((IntPtr)INVALID_HANDLE_VALUE, guidAction, wtd);
                        if (wtd.StateData != IntPtr.Zero)
                        {
                            IntPtr ptrProvData = WTHelperProvDataFromStateData(wtd.StateData);
                            CryptProviderData provData = (CryptProviderData)Marshal.PtrToStructure(ptrProvData, typeof(CryptProviderData));
                            for (int idxSigner = 0; idxSigner < provData.csSigners; idxSigner++)
                            {
                                IntPtr ptrProvSigner = WTHelperGetProvSignerFromChain(ptrProvData, idxSigner, false, 0);

                                CryptProviderSgnr ProvSigner = (CryptProviderSgnr)Marshal.PtrToStructure(ptrProvSigner, typeof(CryptProviderSgnr));
                                CMSG_SIGNER_INFO Signer = (CMSG_SIGNER_INFO)Marshal.PtrToStructure(ProvSigner.psSigner, typeof(CMSG_SIGNER_INFO));

                                VERIFY_SIGNATURE vsign = new VERIFY_SIGNATURE();
                                vsign.Issuer = CryptIntBlobToString(Signer.Issuer, CERT_SIMPLE_NAME_STR);
                                vsign.HashAlgorithm = CryptAlgorythmIdtoOid(Signer.HashAlgorithm);
                                vsign.HashEncryptionAlgorithm = CryptAlgorythmIdtoOid(Signer.HashEncryptionAlgorithm);

                                IntPtr ptrCert = WTHelperGetProvCertFromChain(ptrProvSigner, idxSigner);
                                CryptProviderCert cert = (CryptProviderCert)Marshal.PtrToStructure(ptrCert, typeof(CryptProviderCert));

                                if (cert.cbStruct > 0 && cert.pCert != IntPtr.Zero) vsign.Certificate = new X509Certificate2(cert.pCert);

                                //if (ProvSigner.sftVerifyAsOf.dwHighDateTime != provData.sftSystemTime.dwHighDateTime && ProvSigner.sftVerifyAsOf.dwLowDateTime != provData.sftSystemTime.dwLowDateTime)
                                vsign.Signed = DateTime.FromFileTimeUtc(((long)ProvSigner.sftVerifyAsOf.dwHighDateTime << 32) | (uint)ProvSigner.sftVerifyAsOf.dwLowDateTime);

                                signatures.Add(vsign);
                            };
                        };
                    };
                }
                catch { };
                signs = signatures.ToArray();
                return result;
            }
            catch (Exception e) { ex = e; }
            finally
            {
                if (wtd != null)
                {
                    if (wtd.pSignatureSettings != IntPtr.Zero) Marshal.FreeHGlobal(wtd.pSignatureSettings);
                    wtd.Dispose();
                };
                if (wtfi != null) wtfi.Dispose();
            };
            return WinVerifyTrustResult.NTE_NOT_FOUND;
        }

        #region kernel32.dll

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        static extern uint GetLastError();

        #endregion kernel32.dll

        #region ImageHlp.dll

        [DllImport("Imagehlp.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ImageEnumerateCertificates(IntPtr hFile, uint wTypeFilter, ref uint dwCertCount, IntPtr pIndices, IntPtr pIndexCount);

        [DllImport("Imagehlp.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ImageRemoveCertificate(IntPtr hFile, uint dwCertCount);

        [DllImport("Imagehlp.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ImageGetCertificateData(IntPtr hFile, uint dwCertIndex, IntPtr cert, ref int len);

        [DllImport("Imagehlp.dll", SetLastError = true)]
        private static extern bool ImageGetCertificateHeader(IntPtr hFile, uint dwCertIndex, IntPtr certificateheader);

        #endregion ImageHlp.dll

        #region WinCert

        private enum WIN_CERT_TYPE : short
        {
            WIN_CERT_TYPE_X509 = 0x0001,
            WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002,
            WIN_CERT_TYPE_RESERVED_1 = 0x0003,
            WIN_CERT_TYPE_PKCS1_SIGN = 0x0004,
        }

        private struct WIN_CERTIFICATE
        {
            public uint dwLength;
            public short wRevision;
            public WIN_CERT_TYPE wCertificateType;   // WIN_CERT_TYPE_xxx
            //public byte[] bCertificate;
        }

        #endregion WinCert

        #region SELF

        public struct CHECK_RESULT
        {
            public CHECK_STATUS Status;
            public VERIFY_SIGNATURE[] Signatures;
        }

        public enum CHECK_STATUS
        {
            OK = 0x00,
            NOT_SIGNED = 0x01,
            NOT_TRUSTED = 0x02,
            BAD_THUMBPRINT = 0x03,
            BAD_SIGNATURE = 0x04,
            NO_INFO = 0xFD,
            BAD_FILE = 0xFE,
            ERROR = 0xFF,
        }

        public struct VERIFY_SIGNATURE
        {
            public string Issuer;
            public Oid HashAlgorithm;
            public Oid HashEncryptionAlgorithm;
            public X509Certificate2 Certificate;
            public DateTime Signed;
        }

        #endregion SELF

        public static X509Certificate2[] GetCerificateFileInfo(string fileName, out Exception ex)
        {
            List<X509Certificate2> res = new List<X509Certificate2>();
            ex = null;
            IntPtr hFile = IntPtr.Zero;
            try
            {
                hFile = CreateFile(fileName, GENERIC_READ, FILE_SHARE_READ, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
                if (hFile.ToInt32() == -1) Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());

                uint certCount = 0;
                bool ok = ImageEnumerateCertificates(hFile, CERT_SECTION_TYPE_ANY, ref certCount, IntPtr.Zero, IntPtr.Zero);
                if (!ok) Marshal.ThrowExceptionForHR((int)GetLastError());
                if (certCount > 0)
                {
                    for (uint ci = 0; ci < certCount; ci++)
                    {
                        int len = 0;
                        ok = ImageGetCertificateData(hFile, ci, IntPtr.Zero, ref len);
                        if (!ok && len == 0) continue;

                        IntPtr wincertPtr = Marshal.AllocHGlobal(len);
                        ok = ImageGetCertificateData(hFile, ci, wincertPtr, ref len);
                        if (!ok) { Marshal.FreeHGlobal(wincertPtr); Marshal.ThrowExceptionForHR((int)GetLastError()); };

                        WIN_CERTIFICATE wc = Marshal.PtrToStructure<WIN_CERTIFICATE>(wincertPtr);
                        // if (wc.wCertificateType == WIN_CERT_TYPE.WIN_CERT_TYPE_PKCS_SIGNED_DATA) // https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-win_certificate
                        try
                        {
                            byte[] data = new byte[wc.dwLength - 8];
                            IntPtr ptrd = (IntPtr)((long)wincertPtr + (long)8);
                            Marshal.Copy(ptrd, data, 0, data.Length);
                            X509Certificate2 x = new X509Certificate2(data);
                            //X509Certificate2.CreateFromSignedFile(fileName);
                            res.Add(x);
                        }
                        catch (Exception e) { ex = e; };
                        Marshal.FreeHGlobal(wincertPtr);
                    };
                };
            }
            catch (Exception e) { ex = e; }
            finally
            {
                if (hFile != IntPtr.Zero) CloseHandle(hFile);
            };
            return res.ToArray();
        }

        public static bool RemoveCertificateFileInfo(string fileName, out Exception ex)
        {
            ex = null;
            IntPtr hFile = IntPtr.Zero;
            bool res = false;
            try
            {
                hFile = CreateFile(fileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
                if (hFile.ToInt32() == -1) Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());

                uint certCount = 0;
                bool ok = ImageEnumerateCertificates(hFile, CERT_SECTION_TYPE_ANY, ref certCount, IntPtr.Zero, IntPtr.Zero);
                if (!ok) Marshal.ThrowExceptionForHR((int)GetLastError());
                if (certCount > 0)
                {
                    for (uint ci = 0; ci < certCount; ci++)
                        res = ImageRemoveCertificate(hFile, ci);
                };
            }
            catch (Exception e) { ex = e; }
            finally
            {
                if (hFile != IntPtr.Zero) CloseHandle(hFile);
            };
            return res;
        }

        public static CHECK_RESULT CheckFileCertificate(string fileName, out Exception ex, string thumbprint = null, bool okIfRootTrusted = false, bool okIfCATrusted = false)
        {
            CHECK_RESULT res = new CHECK_RESULT() { Status = CHECK_STATUS.NO_INFO, Signatures = null };

            WinVerifyTrustResult tr = GetSignatureFileInfo(fileName, out VERIFY_SIGNATURE[] signs, out ex);
            res.Signatures = signs;

            if (ex != null) { res.Status = CHECK_STATUS.ERROR; return res; };
            if (tr != WinVerifyTrustResult.Success && tr != WinVerifyTrustResult.TRUST_E_NOSIGNATURE && tr != WinVerifyTrustResult.TRUST_E_BAD_DIGEST && tr != WinVerifyTrustResult.CERT_E_UNTRUSTEDROOT && tr != WinVerifyTrustResult.CERT_E_UNTRUSTEDCA) { res.Status = CHECK_STATUS.BAD_FILE; return res; };
            if (tr == WinVerifyTrustResult.Success) { };
            if (tr == WinVerifyTrustResult.TRUST_E_NOSIGNATURE) { res.Status = CHECK_STATUS.NOT_SIGNED; return res; };
            if (tr == WinVerifyTrustResult.TRUST_E_BAD_DIGEST) { res.Status = CHECK_STATUS.BAD_SIGNATURE; return res; };
            if (tr == WinVerifyTrustResult.CERT_E_UNTRUSTEDROOT && okIfRootTrusted) { res.Status = CHECK_STATUS.OK; return res; };
            if (tr == WinVerifyTrustResult.CERT_E_UNTRUSTEDCA && okIfCATrusted) { res.Status = CHECK_STATUS.OK; return res; };
            if (string.IsNullOrEmpty(thumbprint)) { res.Status = CHECK_STATUS.OK; return res; };

            if (!string.IsNullOrEmpty(thumbprint))
            {
                thumbprint = Regex.Replace(thumbprint.Trim().ToUpper(), "[^A-Z0-9]", "");

                bool hasCerts = false;
                if (signs != null && signs.Length > 0)
                    foreach (VERIFY_SIGNATURE vsign in signs)
                        if (vsign.Certificate != null)
                            hasCerts = true;

                if (hasCerts)
                {
                    foreach (VERIFY_SIGNATURE vsign in signs)
                        if (vsign.Certificate?.Thumbprint.ToUpper() == thumbprint) { res.Status = CHECK_STATUS.OK; return res; };
                }
                else
                {
                    X509Certificate2[] certs = GetCerificateFileInfo(fileName, out ex);
                    if (ex != null) return res;
                    foreach (X509Certificate2 cert in certs)
                        if (cert.Thumbprint.ToUpper() == thumbprint) { res.Status = CHECK_STATUS.OK; return res; };
                };
            };

            if (tr == WinVerifyTrustResult.CERT_E_UNTRUSTEDROOT) { res.Status = CHECK_STATUS.NOT_TRUSTED; return res; };
            if (tr == WinVerifyTrustResult.CERT_E_UNTRUSTEDCA) { res.Status = CHECK_STATUS.NOT_TRUSTED; return res; };
            res.Status = CHECK_STATUS.BAD_THUMBPRINT;
            return res;
        }
    }
}