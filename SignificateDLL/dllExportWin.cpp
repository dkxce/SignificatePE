//
// WORKS BAD
//


#include "pch.h"

typedef unsigned int ALG_ID;


typedef struct _SIGNER_FILE_INFO
{
    DWORD cbSize;
    LPCWSTR pwszFileName;
    HANDLE hFile;
}SIGNER_FILE_INFO, * PSIGNER_FILE_INFO;

typedef struct _CRYPTOAPI_BLOB {
    DWORD cbData;
    BYTE* pbData;
} CRYPT_INTEGER_BLOB, * PCRYPT_INTEGER_BLOB, CRYPT_UINT_BLOB, * PCRYPT_UINT_BLOB, CRYPT_OBJID_BLOB, * PCRYPT_OBJID_BLOB, CERT_NAME_BLOB, * PCERT_NAME_BLOB, CERT_RDN_VALUE_BLOB, * PCERT_RDN_VALUE_BLOB, CERT_BLOB, * PCERT_BLOB, CRL_BLOB, * PCRL_BLOB, DATA_BLOB, * PDATA_BLOB, CRYPT_DATA_BLOB, * PCRYPT_DATA_BLOB, CRYPT_HASH_BLOB, * PCRYPT_HASH_BLOB, CRYPT_DIGEST_BLOB, * PCRYPT_DIGEST_BLOB, CRYPT_DER_BLOB, * PCRYPT_DER_BLOB, CRYPT_ATTR_BLOB, * PCRYPT_ATTR_BLOB;

typedef struct CRYPT_ATTRIBUTE {
    LPSTR            pszObjId;
    DWORD            cValue;
    CRYPT_ATTR_BLOB* rgValue;
} CRYPT_ATTRIBUTE, * PCRYPT_ATTRIBUTE;

typedef struct _SIGNER_BLOB_INFO
{
    DWORD cbSize;
    GUID* pGuidSubject;
    DWORD cbBlob;
    BYTE* pbBlob;
    LPCWSTR pwszDisplayName;
}SIGNER_BLOB_INFO, * PSIGNER_BLOB_INFO;

typedef struct _SIGNER_SUBJECT_INFO
{
    DWORD cbSize;
    DWORD* pdwIndex;
    DWORD dwSubjectChoice;
    union
    {
        SIGNER_FILE_INFO* pSignerFileInfo;
        SIGNER_BLOB_INFO* pSignerBlobInfo;
    };
}SIGNER_SUBJECT_INFO, * PSIGNER_SUBJECT_INFO;

// dwSubjectChoice should be one of the following:
#define SIGNER_SUBJECT_FILE    0x01
#define SIGNER_SUBJECT_BLOB    0x02
#define CALG_SHA_256 	0x0000800c

typedef struct _SIGNER_ATTR_AUTHCODE
{
    DWORD cbSize;
    BOOL fCommercial;
    BOOL fIndividual;
    LPCWSTR pwszName;
    LPCWSTR pwszInfo;
}SIGNER_ATTR_AUTHCODE, * PSIGNER_ATTR_AUTHCODE;

typedef struct _SIGNER_SIGNATURE_INFO
{
    DWORD cbSize;
    ALG_ID algidHash;
    DWORD dwAttrChoice;
    union
    {
        SIGNER_ATTR_AUTHCODE* pAttrAuthcode;
    };
    CRYPT_ATTRIBUTE* psAuthenticated;
    CRYPT_ATTRIBUTE* psUnauthenticated;
}SIGNER_SIGNATURE_INFO, * PSIGNER_SIGNATURE_INFO;

// dwAttrChoice should be one of the following:
#define SIGNER_NO_ATTR          0x00
#define SIGNER_AUTHCODE_ATTR    0x01

typedef struct _SIGNER_PROVIDER_INFO
{
    DWORD cbSize;
    LPCWSTR pwszProviderName;
    DWORD dwProviderType;
    DWORD dwKeySpec;
    DWORD dwPvkChoice;
    union
    {
        LPWSTR pwszPvkFileName;
        LPWSTR pwszKeyContainer;
    };
}SIGNER_PROVIDER_INFO, * PSIGNER_PROVIDER_INFO;

//dwPvkChoice should be one of the following:
#define PVK_TYPE_FILE_NAME       0x01
#define PVK_TYPE_KEYCONTAINER    0x02

typedef struct _SIGNER_SPC_CHAIN_INFO
{
    DWORD cbSize;
    LPCWSTR pwszSpcFile;
    DWORD dwCertPolicy;
    DWORD hCertStore;
}SIGNER_SPC_CHAIN_INFO, * PSIGNER_SPC_CHAIN_INFO;

typedef struct CERT_CONTEXT {
    DWORD dwCertEncodingType;
    BYTE* pbCertEncoded;
    DWORD cbCertEncoded;
    DWORD pCertInfo;
    DWORD hCertStore;
} CERT_CONTEXT, * PCERT_CONTEXT;

typedef struct _SIGNER_CERT_STORE_INFO
{
    DWORD cbSize;
    CERT_CONTEXT* pSigningCert;
    DWORD dwCertPolicy;
    DWORD hCertStore;
}SIGNER_CERT_STORE_INFO, * PSIGNER_CERT_STORE_INFO;

//dwCertPolicy can be a combination of the following flags:
#define SIGNER_CERT_POLICY_STORE            0x01
#define SIGNER_CERT_POLICY_CHAIN            0x02
#define SIGNER_CERT_POLICY_SPC              0x04
#define SIGNER_CERT_POLICY_CHAIN_NO_ROOT    0x08

typedef struct _SIGNER_CERT
{
    DWORD cbSize;
    DWORD dwCertChoice;
    union
    {
        LPCWSTR pwszSpcFile;
        SIGNER_CERT_STORE_INFO* pCertStoreInfo;
        SIGNER_SPC_CHAIN_INFO* pSpcChainInfo;
    };
    HWND hwnd;
}SIGNER_CERT, * PSIGNER_CERT;

//dwCertChoice should be one of the following
#define SIGNER_CERT_SPC_FILE     0x01
#define SIGNER_CERT_STORE        0x02
#define SIGNER_CERT_SPC_CHAIN    0x03

typedef struct _SIGNER_CONTEXT
{
    DWORD cbSize;
    DWORD cbBlob;
    BYTE* pbBlob;
}SIGNER_CONTEXT, * PSIGNER_CONTEXT;

typedef struct _SIGNER_SIGN_EX2_PARAMS
{
    DWORD dwFlags;
    PSIGNER_SUBJECT_INFO pSubjectInfo;
    PSIGNER_CERT pSigningCert;
    PSIGNER_SIGNATURE_INFO pSignatureInfo;
    PSIGNER_PROVIDER_INFO pProviderInfo;
    DWORD dwTimestampFlags;
    PCSTR pszAlgorithmOid;
    PCWSTR pwszTimestampURL;
    CRYPT_ATTRIBUTE* pCryptAttrs;
    PVOID pSipData;
    PSIGNER_CONTEXT* pSignerContext;
    PVOID pCryptoPolicy;
    PVOID pReserved;
} SIGNER_SIGN_EX2_PARAMS, * PSIGNER_SIGN_EX2_PARAMS;

typedef struct _APPX_SIP_CLIENT_DATA
{
    PSIGNER_SIGN_EX2_PARAMS pSignerParams;
    DWORD pAppxSipState;
} APPX_SIP_CLIENT_DATA, * PAPPX_SIP_CLIENT_DATA;

// The equivalent of LPCSTR is string or StringBuilder
extern "C" __declspec(dllexport) HRESULT __cdecl Significate(
    _In_ CERT_CONTEXT* signingCertContext, // X509Certificate2.Handle
    _In_ LPCWSTR packageFilePath)
{
    HRESULT hr = S_OK;
    // LPCWSTR packageFilePath = L"C:\\Downloads\\Runner.exe";

    // Initialize the parameters for SignerSignEx2
    DWORD signerIndex = 0;

    SIGNER_FILE_INFO fileInfo = {};
    fileInfo.cbSize = sizeof(SIGNER_FILE_INFO);
    fileInfo.pwszFileName = packageFilePath;

    SIGNER_SUBJECT_INFO subjectInfo = {};
    subjectInfo.cbSize = sizeof(SIGNER_SUBJECT_INFO);
    subjectInfo.pdwIndex = &signerIndex;
    subjectInfo.dwSubjectChoice = SIGNER_SUBJECT_FILE;
    subjectInfo.pSignerFileInfo = &fileInfo;

    SIGNER_CERT_STORE_INFO certStoreInfo = {};
    certStoreInfo.cbSize = sizeof(SIGNER_CERT_STORE_INFO);
    certStoreInfo.dwCertPolicy = SIGNER_CERT_POLICY_CHAIN_NO_ROOT;
    certStoreInfo.pSigningCert = signingCertContext;

    SIGNER_CERT cert = {};
    cert.cbSize = sizeof(SIGNER_CERT);
    cert.dwCertChoice = SIGNER_CERT_STORE;
    cert.pCertStoreInfo = &certStoreInfo;

    // The algidHash of the signature to be created must match the
    // hash algorithm used to create the app package
    SIGNER_SIGNATURE_INFO signatureInfo = {};
    signatureInfo.cbSize = sizeof(SIGNER_SIGNATURE_INFO);
    signatureInfo.algidHash = CALG_SHA_256;
    signatureInfo.dwAttrChoice = SIGNER_NO_ATTR;

    SIGNER_SIGN_EX2_PARAMS signerParams = {};
    signerParams.pSubjectInfo = &subjectInfo;
    signerParams.pSigningCert = &cert;
    signerParams.pSignatureInfo = &signatureInfo;

    APPX_SIP_CLIENT_DATA sipClientData = {};
    sipClientData.pSignerParams = &signerParams;
    signerParams.pSipData = &sipClientData;

    // Type definition for invoking SignerSignEx2 via GetProcAddress
    typedef HRESULT(WINAPI* SignerSignExFunction)(
        DWORD,
        PSIGNER_SUBJECT_INFO,
        PSIGNER_CERT,
        PSIGNER_SIGNATURE_INFO,
        PSIGNER_PROVIDER_INFO,
        PCWSTR,
        CRYPT_ATTRIBUTE*,
        PVOID,
        PSIGNER_CONTEXT*);

    // Type definition for invoking SignerSignEx2 via GetProcAddress
    typedef HRESULT(WINAPI* SignerSignEx2Function)(
        DWORD,
        PSIGNER_SUBJECT_INFO,
        PSIGNER_CERT,
        PSIGNER_SIGNATURE_INFO,
        PSIGNER_PROVIDER_INFO,
        DWORD,
        PCSTR,
        PCWSTR,
        CRYPT_ATTRIBUTE*,
        PVOID,
        PSIGNER_CONTEXT*,
        PVOID,
        PVOID);

    // Load the SignerSignEx2 function from MSSign32.dll
    HMODULE msSignModule = LoadLibraryEx(
        L"MSSign32.dll",
        NULL,
        LOAD_LIBRARY_SEARCH_SYSTEM32);

    if (msSignModule)
    {
        SignerSignExFunction SignerSignEx = reinterpret_cast<SignerSignExFunction>(
            GetProcAddress(msSignModule, "SignerSignEx"));
        if (SignerSignEx)
        {
            _SIGNER_CONTEXT* pSignerContext = NULL;
            hr = SignerSignEx(
                0,
                signerParams.pSubjectInfo,
                signerParams.pSigningCert,
                signerParams.pSignatureInfo,
                NULL,
                NULL,
                NULL,
                NULL,
                &pSignerContext);
            
            if (hr == 0)
            {
                FreeLibrary(msSignModule);
                return hr;
            };
        }
        else
        {
            DWORD lastError = GetLastError();
            hr = HRESULT_FROM_WIN32(lastError);
        };

        SignerSignEx2Function SignerSignEx2 = reinterpret_cast<SignerSignEx2Function>(
            GetProcAddress(msSignModule, "SignerSignEx2"));
        if (SignerSignEx2)
        {
            hr = SignerSignEx2(
                signerParams.dwFlags,
                signerParams.pSubjectInfo,
                signerParams.pSigningCert,
                signerParams.pSignatureInfo,
                signerParams.pProviderInfo,
                signerParams.dwTimestampFlags,
                signerParams.pszAlgorithmOid,
                signerParams.pwszTimestampURL,
                signerParams.pCryptAttrs,
                signerParams.pSipData,
                signerParams.pSignerContext,
                signerParams.pCryptoPolicy,
                signerParams.pReserved);
        }
        else
        {
            DWORD lastError = GetLastError();
            hr = HRESULT_FROM_WIN32(lastError);
        };

        FreeLibrary(msSignModule);
    }
    else
    {
        DWORD lastError = GetLastError();
        hr = HRESULT_FROM_WIN32(lastError);
    };

    // Free any state used during app package signing
    if (sipClientData.pAppxSipState)
    {
        //sipClientData.pAppxSipState->Release();
    };

    return hr;
}