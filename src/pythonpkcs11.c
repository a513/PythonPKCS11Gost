#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif
#ifdef HAVE_STDLIB_H
#  include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#  include <string.h>
#endif
#ifdef HAVE_STRINGS_H
#  include <strings.h>
#endif
#ifdef _WIN32
#  include <windows.h>
//#define ssize_t long int
#else
//#ifdef HAVE_DLFCN_H
#  include <dlfcn.h>
//#endif
#ifdef HAVE_DL_H
#  include <dl.h>
#endif

#endif //_WIN32
#include <Python.h>
#define PY_SSIZE_T_CLEAN
#define MODULE_SCOPE static

/* PKCS#11 Definitions for the local platform */
#define CK_PTR *
#define CK_DECLARE_FUNCTION(rv, func) rv func
#define CK_DECLARE_FUNCTION_POINTER(rv, func) rv (CK_PTR func)
#define CK_CALLBACK_FUNCTION(rv, func) rv (CK_PTR func)
#define CK_NULL_PTR ((void *) 0)

#ifdef _WIN32
#  pragma pack(push, cryptoki, 1)
#endif

#include "pkcs11.h"
/*LISSI*/
//#include <pkcs11t_gost.h>
#include "pkcs11t_gost.h"
#include "gost_r3411_2012.h"
struct tclpkcs11_handle {
  /* PKCS11 Module Pointers */
  void *base;
  CK_FUNCTION_LIST_PTR pkcs11;

  /* Session Management */
  int session_active;
  CK_SLOT_ID session_slot;
  CK_SESSION_HANDLE session;
};
typedef struct tclpkcs11_interpdata{
  /* Handle Hash Table */
  PyObject *handles;
  unsigned long handles_idx;
} tclpkcs11_interpdata_t;
struct tclpkcs11_interpdata *cd;

#ifdef _WIN32
#  pragma pack(pop, cryptoki)
#endif

int wtable[64] = {
  0x0402, 0x0403, 0x201A, 0x0453, 0x201E, 0x2026, 0x2020, 0x2021,
  0x20AC, 0x2030, 0x0409, 0x2039, 0x040A, 0x040C, 0x040B, 0x040F,
  0x0452, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
  0x007F, 0x2122, 0x0459, 0x203A, 0x045A, 0x045C, 0x045B, 0x045F,
  0x00A0, 0x040E, 0x045E, 0x0408, 0x00A4, 0x0490, 0x00A6, 0x00A7,
  0x0401, 0x00A9, 0x0404, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x0407,
  0x00B0, 0x00B1, 0x0406, 0x0456, 0x0491, 0x00B5, 0x00B6, 0x00B7,
0x0451, 0x2116, 0x0454, 0x00BB, 0x0458, 0x0405, 0x0455, 0x0457};

int utf8_to_win1251(const char* text, char* wtext)
{
  int wc, uc;
  int i, j, k, m;
  if (!wtext)
  return 0;
  i=0;
  j=0;
  while ((unsigned int)i<strlen(text))
  {
    /* read Unicode character */
    /* read first UTF-8 byte */
    wc = (unsigned char)text[i++];
    /* 11111xxx - not symbol (BOM etc) */
    if (wc>=0xF8) {
      m = -1;
    }
    /* 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx -> 0x00010000 — 0x001FFFFF */
    else if (wc>=0xF0) {
      uc = (wc&0x07);
      m = 3;
    }
    /* 1110xxxx 10xxxxxx 10xxxxxx -> 0x00000800 — 0x0000FFFF */
    else if (wc>=0xE0) {
      uc = (wc&0x0F);
      m = 2;
    }
    /* 110xxxxx 10xxxxxx -> 0x00000080 — 0x000007FF */
    else if (wc>=0xC0) {
      uc = (wc&0x1F);
      m = 1;
    }
    /* 0xxxxxxx -> 0x00000000 — 0x0000007F */
    else if (wc<=0x7F) {
      uc = wc;
      m = 0;
    }
    /* 10xxxxxx - data error! */
    else {
      m = -1;
    }
    /* read m UTF-8 bytes (10xxxxxx) */
    k = 1;
    wc = 0;
    while (k<=m && wc<=0xBF)
    {
      wc = (unsigned char)text[i++];
      uc <<= 6;
      uc += (wc&0x3F);
      k++;
    }
    if (wc>0xBF || m<0) {
      uc = -1;
    }
    /* Unicode to Windows-1251 */
    if (uc<0) {
      wc = -1;
    }
    else if (uc<=0x7F) /* ASCII */
    {
      wc = uc;
    }
    else if (uc>=0x0410 && uc<=0x042F) /* А-Я */
    {
      wc = uc - 0x410 + 0xC0;
    }
    else if (uc>=0x0430 && uc<=0x044F) /* а-я */
    {
      wc = uc - 0x0430 + 0xE0;
    }
    else /* Ђ-ї */
    {
      /* search in wtable */
      k = 0;
      while (k<64 && wtable[k]!=uc)
      {
        k++;
      }
      if (k<64)
      {
        wc = k + 0x80;
      }
      else
      {
        wc = '?';
      }
    }
    /* save Windows-1251 character */
    if (wc>0)
    {
      wtext[j++] = (char)wc;
    }
  }
  wtext[j] = 0x00;
  return 1;
}


unsigned char *wrap_for_asn1(unsigned char type, char *prefix, unsigned char *wrap){
  unsigned long length;
  int buflen = 0;
  unsigned char *buf;
  char *format;
  char f0[] = "%02x%02x%s%s";
  char f1[] = "%02x81%02x%s%s";
  char f2[] = "%02x82%04x%s%s";
  char f3[] = "%02x83%06x%s%s";
  char f4[] = "%02x84%08x%s%s";
  length = (unsigned long)(strlen((const char*)wrap) + strlen((const char*)prefix))/2;
  buf = malloc(length + 1 + 2 + length * 2);
  buflen += ( length < 0x80 ? 1:
  length <= 0xff ? 2:
  length <= 0xffff ? 3:
  length <= 0xffffff ? 4: 5);
  switch (buflen - 1) {
    case 0:
      format = f0;
      break;
    case 1:
      format = f1;
      break;
    case 2:
      format = f2;
      break;
    case 3:
      format = f3;
      break;
    case 4:
      format = f4;
      break;
  }
  sprintf((char*)buf, (const char *)format, type, length, prefix,wrap);
  //    fprintf(stderr, "LENGTH=%lu, BUFLEN=%i\n", length, buflen);
  return (buf);
}

/////////////Parse Certificate///////////////////////////////////
struct asn1_object {
  unsigned long tag;
  unsigned long size;
  void *contents;

  unsigned long asn1rep_len;
  void *asn1rep;
};

struct x509_object {
  struct asn1_object wholething;
  struct asn1_object certificate;
  struct asn1_object version;
  struct asn1_object serial_number;
  struct asn1_object signature_algo;
  struct asn1_object issuer;
  struct asn1_object validity;
  struct asn1_object subject;
  struct asn1_object pubkeyinfo;
    struct asn1_object pubkey_algoid;
	struct asn1_object pubkey_algo;
	struct asn1_object pubkey_algoparm;
    struct asn1_object pubkey;
//LISSI
  struct asn1_object signature_type;
  struct asn1_object signature;
//  struct asn1_object signature_end;
};

static int _asn1_x509_read_asn1_object(unsigned char *buf, size_t buflen, va_list *args) {
  unsigned char small_object_size;
  unsigned char *buf_p;
  struct asn1_object *outbuf;

  outbuf = va_arg(*args, struct asn1_object *);

  if (outbuf == NULL) {
    return(0);
  }

  if (buflen == 0) {
    return(-1);
  }

  buf_p = buf;

  outbuf->tag = *buf_p;
  buf_p++;
  buflen--;

  /* NULL Tag -- no size is required */
  if (outbuf->tag == 0x00) {
    outbuf->size = 0;
    outbuf->asn1rep_len = 1;
    outbuf->asn1rep = buf;

    return(_asn1_x509_read_asn1_object(buf_p, buflen, args));
  }

  if (buflen == 0) {
    return(-1);
  }

  small_object_size = *buf_p;
  buf_p++;
  buflen--;
  if (buflen == 0) {
    return(-1);
  }

  if ((small_object_size & 0x80) == 0x80) {
    outbuf->size = 0;

    for (small_object_size ^= 0x80; small_object_size; small_object_size--) {
      outbuf->size <<= 8;
      outbuf->size += *buf_p;

      buf_p++;
      buflen--;

      if (buflen == 0) {
        break;
      }
    }
  } else {
    outbuf->size = small_object_size;
  }

  if (outbuf->size > buflen) {
    return(-1);
  }

  if (buflen != 0) {
    outbuf->contents = buf_p;
  }

  outbuf->asn1rep_len = (unsigned long) (outbuf->size + (buf_p - buf));
  outbuf->asn1rep = buf;

  buf_p += outbuf->size;
  buflen -= outbuf->size;

  return(_asn1_x509_read_asn1_object(buf_p, buflen, args));
}

static int asn1_x509_read_asn1_object(unsigned char *buf, size_t buflen, ...) {
  va_list args;
  int retval;

  va_start(args, buflen);

  retval = _asn1_x509_read_asn1_object(buf, buflen, &args);

  va_end(args);

  return(retval);
}

static int asn1_x509_read_object(unsigned char *buf, size_t buflen, struct x509_object *outbuf) {
  int read_ret;

  read_ret = asn1_x509_read_asn1_object(buf, buflen, &outbuf->wholething, NULL);
  if (read_ret != 0) {
    //		CACKEY_DEBUG_PRINTF("Failed at reading the contents from the wrapper");

    return(-1);
  }

  read_ret = asn1_x509_read_asn1_object(outbuf->wholething.contents, outbuf->wholething.size, &outbuf->certificate, &outbuf->signature_type, &outbuf->signature, NULL);

  if (read_ret != 0) {
    //		CACKEY_DEBUG_PRINTF("Failed at reading the certificate from the contents");

    return(-1);
  }

  read_ret = asn1_x509_read_asn1_object(outbuf->certificate.contents, outbuf->certificate.size, &outbuf->version, &outbuf->serial_number, &outbuf->signature_algo, &outbuf->issuer, &outbuf->validity, &outbuf->subject, &outbuf->pubkeyinfo, NULL);
  if (read_ret != 0) {
    /* Try again without a version tag (X.509v1) */
    outbuf->version.tag = 0;
    outbuf->version.size = 0;
    outbuf->version.contents = NULL;
    outbuf->version.asn1rep_len = 0;
    outbuf->version.asn1rep = NULL;
    read_ret = asn1_x509_read_asn1_object(outbuf->certificate.contents, outbuf->certificate.size, &outbuf->serial_number, &outbuf->signature_algo, &outbuf->issuer, &outbuf->validity, &outbuf->subject, &outbuf->pubkeyinfo, NULL);
    if (read_ret != 0) {
      //			CACKEY_DEBUG_PRINTF("Failed at reading the certificate components from the certificate");

      return(-1);
    }
  }

  read_ret = asn1_x509_read_asn1_object(outbuf->pubkeyinfo.contents, outbuf->pubkeyinfo.size, &outbuf->pubkey_algoid, &outbuf->pubkey, NULL);
  if (read_ret != 0) {
    //		CACKEY_DEBUG_PRINTF("Failed at reading the public key from the certificate components");

    return(-1);
  }
//LISSI
/*
  read_ret = asn1_x509_read_asn1_object(outbuf->signature.contents, outbuf->signature.size, &outbuf->signature_end,  NULL);
  if (read_ret != 0) {
    //		CACKEY_DEBUG_PRINTF("Failed at reading the public key from the certificate components");

    return(-1);
  }
*/

  return(0);
}

/////////////End Parse Certificate///////////////////////////////////

/*
* Tcl <--> PKCS11 Bridge Functions
*/

MODULE_SCOPE char *tclpkcs11_pkcs11_error(CK_RV errorCode) {
  switch (errorCode) {
    case CKR_OK:
      return("PKCS11_OK OK");
    case CKR_CANCEL:
      return("PKCS11_ERROR CANCEL");
    case CKR_HOST_MEMORY:
      return("PKCS11_ERROR HOST_MEMORY");
    case CKR_SLOT_ID_INVALID:
      return("PKCS11_ERROR SLOT_ID_INVALID");
    case CKR_GENERAL_ERROR:
      return("PKCS11_ERROR GENERAL_ERROR");
    case CKR_FUNCTION_FAILED:
      return("PKCS11_ERROR FUNCTION_FAILED");
    case CKR_ARGUMENTS_BAD:
      return("PKCS11_ERROR ARGUMENTS_BAD");
    case CKR_NO_EVENT:
      return("PKCS11_ERROR NO_EVENT");
    case CKR_NEED_TO_CREATE_THREADS:
      return("PKCS11_ERROR NEED_TO_CREATE_THREADS");
    case CKR_CANT_LOCK:
      return("PKCS11_ERROR CANT_LOCK");
    case CKR_ATTRIBUTE_READ_ONLY:
      return("PKCS11_ERROR ATTRIBUTE_READ_ONLY");
    case CKR_ATTRIBUTE_SENSITIVE:
      return("PKCS11_ERROR ATTRIBUTE_SENSITIVE");
    case CKR_ATTRIBUTE_TYPE_INVALID:
      return("PKCS11_ERROR ATTRIBUTE_TYPE_INVALID");
    case CKR_ATTRIBUTE_VALUE_INVALID:
      return("PKCS11_ERROR ATTRIBUTE_VALUE_INVALID");
    case CKR_DATA_INVALID:
      return("PKCS11_ERROR DATA_INVALID");
    case CKR_DATA_LEN_RANGE:
      return("PKCS11_ERROR DATA_LEN_RANGE");
    case CKR_DEVICE_ERROR:
      return("PKCS11_ERROR DEVICE_ERROR");
    case CKR_DEVICE_MEMORY:
      return("PKCS11_ERROR DEVICE_MEMORY");
    case CKR_DEVICE_REMOVED:
      return("PKCS11_ERROR DEVICE_REMOVED");
    case CKR_ENCRYPTED_DATA_INVALID:
      return("PKCS11_ERROR ENCRYPTED_DATA_INVALID");
    case CKR_ENCRYPTED_DATA_LEN_RANGE:
      return("PKCS11_ERROR ENCRYPTED_DATA_LEN_RANGE");
    case CKR_FUNCTION_CANCELED:
      return("PKCS11_ERROR FUNCTION_CANCELED");
    case CKR_FUNCTION_NOT_PARALLEL:
      return("PKCS11_ERROR FUNCTION_NOT_PARALLEL");
    case CKR_FUNCTION_NOT_SUPPORTED:
      return("PKCS11_ERROR FUNCTION_NOT_SUPPORTED");
    case CKR_KEY_HANDLE_INVALID:
      return("PKCS11_ERROR KEY_HANDLE_INVALID");
    case CKR_KEY_SIZE_RANGE:
      return("PKCS11_ERROR KEY_SIZE_RANGE");
    case CKR_KEY_TYPE_INCONSISTENT:
      return("PKCS11_ERROR KEY_TYPE_INCONSISTENT");
    case CKR_KEY_NOT_NEEDED:
      return("PKCS11_ERROR KEY_NOT_NEEDED");
    case CKR_KEY_CHANGED:
      return("PKCS11_ERROR KEY_CHANGED");
    case CKR_KEY_NEEDED:
      return("PKCS11_ERROR KEY_NEEDED");
    case CKR_KEY_INDIGESTIBLE:
      return("PKCS11_ERROR KEY_INDIGESTIBLE");
    case CKR_KEY_FUNCTION_NOT_PERMITTED:
      return("PKCS11_ERROR KEY_FUNCTION_NOT_PERMITTED");
    case CKR_KEY_NOT_WRAPPABLE:
      return("PKCS11_ERROR KEY_NOT_WRAPPABLE");
    case CKR_KEY_UNEXTRACTABLE:
      return("PKCS11_ERROR KEY_UNEXTRACTABLE");
    case CKR_MECHANISM_INVALID:
      return("PKCS11_ERROR MECHANISM_INVALID");
    case CKR_MECHANISM_PARAM_INVALID:
      return("PKCS11_ERROR MECHANISM_PARAM_INVALID");
    case CKR_OBJECT_HANDLE_INVALID:
      return("PKCS11_ERROR OBJECT_HANDLE_INVALID");
    case CKR_OPERATION_ACTIVE:
      return("PKCS11_ERROR OPERATION_ACTIVE");
    case CKR_OPERATION_NOT_INITIALIZED:
      return("PKCS11_ERROR OPERATION_NOT_INITIALIZED");
    case CKR_PIN_INCORRECT:
      return("PKCS11_ERROR PIN_INCORRECT");
    case CKR_PIN_INVALID:
      return("PKCS11_ERROR PIN_INVALID");
    case CKR_PIN_LEN_RANGE:
      return("PKCS11_ERROR PIN_LEN_RANGE");
    case CKR_PIN_EXPIRED:
      return("PKCS11_ERROR PIN_EXPIRED");
    case CKR_PIN_LOCKED:
      return("PKCS11_ERROR PIN_LOCKED");
    case CKR_SESSION_CLOSED:
      return("PKCS11_ERROR SESSION_CLOSED");
    case CKR_SESSION_COUNT:
      return("PKCS11_ERROR SESSION_COUNT");
    case CKR_SESSION_HANDLE_INVALID:
      return("PKCS11_ERROR SESSION_HANDLE_INVALID");
    case CKR_SESSION_PARALLEL_NOT_SUPPORTED:
      return("PKCS11_ERROR SESSION_PARALLEL_NOT_SUPPORTED");
    case CKR_SESSION_READ_ONLY:
      return("PKCS11_ERROR SESSION_READ_ONLY");
    case CKR_SESSION_EXISTS:
      return("PKCS11_ERROR SESSION_EXISTS");
    case CKR_SESSION_READ_ONLY_EXISTS:
      return("PKCS11_ERROR SESSION_READ_ONLY_EXISTS");
    case CKR_SESSION_READ_WRITE_SO_EXISTS:
      return("PKCS11_ERROR SESSION_READ_WRITE_SO_EXISTS");
    case CKR_SIGNATURE_INVALID:
      return("PKCS11_ERROR SIGNATURE_INVALID");
    case CKR_SIGNATURE_LEN_RANGE:
      return("PKCS11_ERROR SIGNATURE_LEN_RANGE");
    case CKR_TEMPLATE_INCOMPLETE:
      return("PKCS11_ERROR TEMPLATE_INCOMPLETE");
    case CKR_TEMPLATE_INCONSISTENT:
      return("PKCS11_ERROR TEMPLATE_INCONSISTENT");
    case CKR_TOKEN_NOT_PRESENT:
      return("PKCS11_ERROR TOKEN_NOT_PRESENT");
    case CKR_TOKEN_NOT_RECOGNIZED:
      return("PKCS11_ERROR TOKEN_NOT_RECOGNIZED");
    case CKR_TOKEN_WRITE_PROTECTED:
      return("PKCS11_ERROR TOKEN_WRITE_PROTECTED");
    case CKR_UNWRAPPING_KEY_HANDLE_INVALID:
      return("PKCS11_ERROR UNWRAPPING_KEY_HANDLE_INVALID");
    case CKR_UNWRAPPING_KEY_SIZE_RANGE:
      return("PKCS11_ERROR UNWRAPPING_KEY_SIZE_RANGE");
    case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT:
      return("PKCS11_ERROR UNWRAPPING_KEY_TYPE_INCONSISTENT");
    case CKR_USER_ALREADY_LOGGED_IN:
      return("PKCS11_ERROR USER_ALREADY_LOGGED_IN");
    case CKR_USER_NOT_LOGGED_IN:
      return("PKCS11_ERROR USER_NOT_LOGGED_IN");
    case CKR_USER_PIN_NOT_INITIALIZED:
      return("PKCS11_ERROR USER_PIN_NOT_INITIALIZED");
    case CKR_USER_TYPE_INVALID:
      return("PKCS11_ERROR USER_TYPE_INVALID");
    case CKR_USER_ANOTHER_ALREADY_LOGGED_IN:
      return("PKCS11_ERROR USER_ANOTHER_ALREADY_LOGGED_IN");
    case CKR_USER_TOO_MANY_TYPES:
      return("PKCS11_ERROR USER_TOO_MANY_TYPES");
    case CKR_WRAPPED_KEY_INVALID:
      return("PKCS11_ERROR WRAPPED_KEY_INVALID");
    case CKR_WRAPPED_KEY_LEN_RANGE:
      return("PKCS11_ERROR WRAPPED_KEY_LEN_RANGE");
    case CKR_WRAPPING_KEY_HANDLE_INVALID:
      return("PKCS11_ERROR WRAPPING_KEY_HANDLE_INVALID");
    case CKR_WRAPPING_KEY_SIZE_RANGE:
      return("PKCS11_ERROR WRAPPING_KEY_SIZE_RANGE");
    case CKR_WRAPPING_KEY_TYPE_INCONSISTENT:
      return("PKCS11_ERROR WRAPPING_KEY_TYPE_INCONSISTENT");
    case CKR_RANDOM_SEED_NOT_SUPPORTED:
      return("PKCS11_ERROR RANDOM_SEED_NOT_SUPPORTED");
    case CKR_RANDOM_NO_RNG:
      return("PKCS11_ERROR RANDOM_NO_RNG");
    case CKR_DOMAIN_PARAMS_INVALID:
      return("PKCS11_ERROR DOMAIN_PARAMS_INVALID");
    case CKR_BUFFER_TOO_SMALL:
      return("PKCS11_ERROR BUFFER_TOO_SMALL");
    case CKR_SAVED_STATE_INVALID:
      return("PKCS11_ERROR SAVED_STATE_INVALID");
    case CKR_INFORMATION_SENSITIVE:
      return("PKCS11_ERROR INFORMATION_SENSITIVE");
    case CKR_STATE_UNSAVEABLE:
      return("PKCS11_ERROR STATE_UNSAVEABLE");
    case CKR_CRYPTOKI_NOT_INITIALIZED:
      return("PKCS11_ERROR CRYPTOKI_NOT_INITIALIZED");
    case CKR_CRYPTOKI_ALREADY_INITIALIZED:
      return("PKCS11_ERROR CRYPTOKI_ALREADY_INITIALIZED");
    case CKR_MUTEX_BAD:
      return("PKCS11_ERROR MUTEX_BAD");
    case CKR_MUTEX_NOT_LOCKED:
      return("PKCS11_ERROR MUTEX_NOT_LOCKED");
    case CKR_NEW_PIN_MODE:
      return("PKCS11_ERROR NEW_PIN_MODE");
    case CKR_NEXT_OTP:
      return("PKCS11_ERROR NEXT_OTP");
    case CKR_FUNCTION_REJECTED:
      return("PKCS11_ERROR FUNCTION_REJECTED");
    case CKR_VENDOR_DEFINED:
      return("PKCS11_ERROR VENDOR_DEFINED");
  }

  return("PKCS11_ERROR UNKNOWN");
}

/*LISSI*/
char *get_mechanism_name(CK_ULONG mech)
{
  switch (mech) {
    case CKM_GOSTR3410_KEY_PAIR_GEN:
      return "CKM_GOSTR3410_KEY_PAIR_GEN";
    case CKM_GOSTR3410_512_KEY_PAIR_GEN:
      return "CKM_GOSTR3410_512_KEY_PAIR_GEN";
    case CKM_GOSTR3410:
      return "CKM_GOSTR3410";
    case CKM_GOSTR3410_512:
      return "CKM_GOSTR3410_512";
    case CKM_GOSTR3410_WITH_GOSTR3411:
      return "CKM_GOSTR3410_WITH_GOSTR3411";
    case CKM_GOSTR3410_WITH_GOSTR3411_12_256:
      return "CKM_GOSTR3410_WITH_GOSTR3411_12_256";
    case CKM_GOSTR3410_WITH_GOSTR3411_12_512:
      return "CKM_GOSTR3410_WITH_GOSTR3411_12_512";
    case CKM_GOSTR3410_KEY_WRAP:
      return "CKM_GOSTR3410_KEY_WRAP";
    case CKM_GOSTR3410_DERIVE:
      return "CKM_GOSTR3410_DERIVE";
    case CKM_GOSTR3410_12_DERIVE:
      return "CKM_GOSTR3410_12_DERIVE";
    case CKM_GOSTR3410_2012_VKO_256:
      return "CKM_GOSR3410_2012_VKO_256";
    case CKM_GOSTR3410_2012_VKO_512:
      return "CKM_GOSR3410_2012_VKO_512";
    case CKM_KDF_4357:
      return "CKM_KDF_4357";
    case CKM_KDF_GOSTR3411_2012_256:
      return "CKM_KDF_GOSTR3411_2012_256";
    case CKM_KDF_TREE_GOSTR3411_2012_256:
      return "CKM_KDF_TREE_GOSTR3411_2012_256";
    case CKM_GOSTR3411:
      return "CKM_GOSTR3411";
    case CKM_GOSTR3411_12_256:
      return "CKM_GOSTR3411_12_256";
    case CKM_GOSTR3411_12_512:
      return "CKM_GOSTR3411_12_512";
    case CKM_GOSTR3411_HMAC:
      return "CKM_GOSTR3411_HMAC";
    case CKM_GOSTR3411_12_256_HMAC:
      return "CKM_GOSTR3411_12_256_HMAC";
    case CKM_GOSTR3411_12_512_HMAC:
      return "CKM_GOSTR3411_12_512_HMAC";
    case CKM_GOST_GENERIC_SECRET_KEY_GEN:
      return "CKM_GOST_GENERIC_SECRET_KEY_GEN";
    case CKM_GOST_CIPHER_KEY_GEN:
      return "CKM_GOST_CIPHER_KEY_GEN";
    case CKM_GOST_CIPHER_ECB:
      return "CKM_GOST_CIPHER_ECB";
    case CKM_GOST_CIPHER_CBC:
      return "CKM_GOST_CIPHER_CBC";
    case CKM_GOST_CIPHER_CTR:
      return "CKM_GOST_CIPHER_CTR";
    case CKM_GOST_CIPHER_OFB:
      return "CKM_GOST_CIPHER_OFB";
    case CKM_GOST_CIPHER_CFB:
      return "CKM_GOST_CIPHER_CFB";
    case CKM_GOST_CIPHER_OMAC:
      return "CKM_GOST_CIPHER_OMAC";
    case CKM_GOST_CIPHER_ACPKM_CTR:
      return "CKM_GOST_CIPHER_ACPKM_CTR";
    case CKM_GOST_CIPHER_ACPKM_OMAC:
      return "CKM_GOST_CIPHER_ACPKM_OMAC";
    case CKM_GOST_CIPHER_KEY_WRAP:
      return "CKM_GOST_CIPHER_KEY_WRAP";
    case CKM_GOST_CIPHER_PKCS8_KEY_WRAP:
      return "CKM_GOST_CIPHER_PKCS8_KEY_WRAP";
    case CKM_GOST28147_KEY_GEN:
      return "CKM_GOST28147_KEY_GEN";
    case CKM_GOST28147_ECB:
      return "CKM_GOST28147_ECB";
    case CKM_GOST28147:
      return "CKM_GOST28147";
    case CKM_GOST28147_MAC:
      return "CKM_GOST28147_MAC";
    case CKM_GOST28147_KEY_WRAP:
      return "CKM_GOST28147_KEY_WRAP";
    case CKM_GOST28147_CNT:
      return "CKM_GOST28147_CNT";
    case CKM_KUZNYECHIK_KEY_GEN:
      return "CKM_KUZNYECHIK_KEY_GEN";
    case CKM_KUZNYECHIK_ECB:
      return "CKM_KUZNYECHIK_ECB";
    case CKM_KUZNYECHIK_CBC:
      return "CKM_KUZNYECHIK_CBC";
    case CKM_KUZNYECHIK_CTR:
      return "CKM_KUZNYECHIK_CTR";
    case CKM_KUZNYECHIK_OFB:
      return "CKM_KUZNYECHIK_OFB";
    case CKM_KUZNYECHIK_CFB:
      return "CKM_KUZNYECHIK_CFB";
    case CKM_KUZNYECHIK_OMAC:
      return "CKM_KUZNYECHIK_OMAC";
    case CKM_KUZNYECHIK_ACPKM_CTR:
      return "CKM_KUZNYECHIK_ACPKM_CTR";
    case CKM_KUZNYECHIK_ACPKM_OMAC:
      return "CKM_KUZNYECHIK_ACPKM_OMAC";
    case CKM_KUZNYECHIK_KEY_WRAP:
      return "CKM_KUZNYECHIK_KEY_WRAP";
    case CKM_MAGMA_KEY_GEN:
      return "CKM_MAGMA_KEY_GEN";
    case CKM_MAGMA_ECB:
      return "CKM_MAGMA_ECB";
    case CKM_MAGMA_CBC:
      return "CKM_MAGMA_CBC";
    case CKM_MAGMA_CTR:
      return "CKM_MAGMA_CTR";
    case CKM_MAGMA_OFB:
      return "CKM_MAGMA_OFB";
    case CKM_MAGMA_CFB:
      return "CKM_MAGMA_CFB";
    case CKM_MAGMA_OMAC:
      return "CKM_MAGMA_OMAC";
    case CKM_MAGMA_ACPKM_CTR:
      return "CKM_MAGMA_ACPKM_CTR";
    case CKM_MAGMA_ACPKM_OMAC:
      return "CKM_MAGMA_ACPKM_OMAC";
    case CKM_MAGMA_KEY_WRAP:
      return "CKM_MAGMA_KEY_WRAP";
    case CKM_TLS_GOST_PRF:
      return "CKM_TLS_GOST_PRF";
    case CKM_TLS_GOST_PRE_MASTER_KEY_GEN:
      return "CKM_TLS_GOST_PRE_MASTER_KEY_GEN";
    case CKM_TLS_GOST_MASTER_KEY_DERIVE:
      return "CKM_TLS_GOST_MASTER_KEY_DERIVE";
    case CKM_TLS_GOST_KEY_AND_MAC_DERIVE:
      return "CKM_TLS_GOST_KEY_AND_MAC_DERIVE";
    case CKM_TLS_GOST_PRF_2012_256:
      return "CKM_TLS_GOST_PRF_2012_256";
    case CKM_TLS_GOST_PRF_2012_512:
      return "CKM_TLS_GOST_PRF_2012_512";
    case CKM_TLS12_MASTER_KEY_DERIVE:
      return "CKM_TLS12_MASTER_KEY_DERIVE";
    case CKM_TLS12_KEY_AND_MAC_DERIVE:
      return "CKM_TLS12_KEY_AND_MAC_DERIVE";
    case CKM_TLS_MAC:
      return "CKM_TLS_MAC";
    case CKM_TLS_KDF:
      return "CKM_TLS_KDF";
    case CKM_TLS_TREE_GOSTR3411_2012_256:
      return "CKM_TLS_TREE_GOSTR3411_2012_256";
    case CKM_PBA_GOSTR3411_WITH_GOSTR3411_HMAC:
      return "CKM_PBA_GOSTR3411_WITH_GOSTR3411_HMAC";
    case CKM_GOST28147_PKCS8_KEY_WRAP:
      return "CKM_GOST28147_PKCS8_KEY_WRAP";
    case CKM_GOSTR3410_PUBLIC_KEY_DERIVE:
      return "CKM_GOSTR3410_PUBLIC_KEY_DERIVE";
    case CKM_LISSI_GOSTR3410_PUBLIC_KEY_DERIVE:
      return "CKM_LISSI_GOSTR3410_PUBLIC_KEY_DERIVE";
    case CKM_EXTRACT_KEY_FROM_KEY:
      return "CKM_EXTRACT_KEY_FROM_KEY";
    case CKM_PKCS5_PBKD2:
      return "CKM_PKCS5_PBKD2";
    case CKM_SHA_1:
      return "CKM_SHA_1";
    case CKM_MD5:
      return "CKM_MD5";
    case CKM_VENDOR_DEFINED:
      return "CKM_VENDOR_DEFINED";
    default:
      return (char *)NULL;
  }
}

/*oid ro hex + asn*/
#define digitp(p)   (*(p) >= '0' && *(p) <= '9')
#define hexdigitp(a) (digitp (a)                     \
                      || (*(a) >= 'A' && *(a) <= 'F')  \
                      || (*(a) >= 'a' && *(a) <= 'f'))

static size_t
make_flagged_int (unsigned long value, unsigned char *buf, size_t buflen)
{
  int more = 0;
  int shift;

  /* fixme: figure out the number of bits in an ulong and start with
     that value as shift (after making it a multiple of 7) a more
     straigtforward implementation is to do it in reverse order using
     a temporary buffer - saves a lot of compares */
  for (more=0, shift=28; shift > 0; shift -= 7)
    {
      if (more || value >= (1<<shift))
        {
          buf[buflen++] = 0x80 | (value >> shift);
          value -= (value >> shift) << shift;
          more = 1;
        }
    }
  buf[buflen++] = value;
  return buflen;
}
int oid_from_str (const char *string, unsigned char **rbuf, size_t *rlength)
{
  unsigned char *buf;
  unsigned char *bufasn;
  size_t buflen;
  unsigned long val1, val;
  const char *endp;
  int arcno;

  if (!string || !rbuf || !rlength)
    return -1;
  *rbuf = NULL;
  *rlength = 0;

  /* we allow the OID to be prefixed with either "oid." or "OID." */
  if ( !strncmp (string, "oid.", 4) || !strncmp (string, "OID.", 4))
    string += 4;

  if (!*string)
    return -1;

  /* we can safely assume that the encoded OID is shorter than the string */
//  buf = malloc ( strlen(string) + 2);
  bufasn = malloc ( strlen(string) + 2 + 2);
  buf = bufasn + 2;
  if (!buf)
    return -1;
  buflen = 0;

  val1 = 0; /* avoid compiler warnings */
  arcno = 0;
  do {
    arcno++;
    val = strtoul (string, (char**)&endp, 10);
    if (!digitp (string) || !(*endp == '.' || !*endp))
      {
        free (buf);
        return -1;
      }
    if (*endp == '.')
      string = endp+1;

    if (arcno == 1)
      {
        if (val > 2)
          break; /* not allowed, error catched below */
        val1 = val;
      }
    else if (arcno == 2)
      { /* need to combine the first to arcs in one octet */
        if (val1 < 2)
          {
            if (val > 39)
              {
                free (buf);
                return -1;
              }
            buf[buflen++] = val1*40 + val;
          }
        else
          {
            val += 80;
            buflen = make_flagged_int (val, buf, buflen);
          }
      }
    else
      {
        buflen = make_flagged_int (val, buf, buflen);
      }
  } while (*endp == '.');

  if (arcno == 1)
    { /* it is not possible to encode only the first arc */
      free (buf);
      return -1;
    }
//ASN
  bufasn[0] = 0x06;
  bufasn[1] = buflen;
  *rbuf = bufasn;
  *rlength = buflen + 2;
  return 0;
}
PyObject *tclpkcs11_bytearray_to_string(const unsigned char *data, unsigned long datalen) {
  static char alphabet[] = "0123456789abcdef";
  unsigned long idx, bufidx;
  PyObject *retval;
  unsigned char *buf;
  //fprintf (stderr, "tclpkcs11_bytearray_to_string: LEN1=%lu\n", datalen);
  buf = (unsigned char *) malloc(datalen*2 + 1);

  if (data == NULL) {
    return(Py_BuildValue("s", ""));
  }

  for (bufidx = idx = 0; (idx < datalen) && (bufidx < (datalen*2 + 1)); idx++) {

    buf[bufidx++] = alphabet[(data[idx] >> 4) & 0xf];
    buf[bufidx++] = alphabet[data[idx] & 0xf];
  }
  retval = Py_BuildValue("s#",(unsigned char *) buf, bufidx);
  free(buf);
  return(retval);
}

MODULE_SCOPE unsigned long tclpkcs11_string_to_bytearray(PyObject *data, unsigned char *outbuf, unsigned long outbuflen) {
  unsigned long outbufidx = 0;
  unsigned char tmpbuf[5];
  char *str;
  int tmpint;
  if (outbuf == NULL) {
    return(0);
  }

  PyArg_Parse(data, "s", &str);
//fprintf(stderr, "CERT=%s\n", str);
  if (!str) {
    return(0);
  }

  tmpbuf[0] = '0';
  tmpbuf[1] = 'x';
  tmpbuf[4] = '\0';

  for (; *str; str++) {
    tmpbuf[2] = *str;

    str++;
    if (!*str) {
      break;
    }

    tmpbuf[3] = *str;

    if (isdigit (tmpbuf[2])) {
	tmpint = (tmpbuf[2] - '0') * 16; // * 16 + (tmpbuf[3] - '0');
    } else {
	tmpint = (tolower(tmpbuf[2]) - 'a' + 10) * 16; // * 16 + (tmpbuf[3] - '0');
    }
    if (isdigit(tmpbuf[3])) {
	tmpint += (tmpbuf[3] - '0');
    } else {
	tmpint += (tolower(tmpbuf[3]) - 'a' + 10);
    }
    outbuf[outbufidx] = (unsigned char)tmpint;
    outbufidx++;

    if (outbufidx >= outbuflen) {
      break;
    }
  }

  return(outbufidx);
}


/* Convience function to start a session if one is not already active */
MODULE_SCOPE int tclpkcs11_start_session(struct tclpkcs11_handle *handle, CK_SLOT_ID slot) {
  CK_SESSION_HANDLE tmp_session;
  CK_RV chk_rv;

  if (handle->session_active) {
    if (handle->session_slot == slot) {
      return(CKR_OK);
    }

    /* Close the existing session and create a new one */
    handle->session_active = 0;
    chk_rv = handle->pkcs11->C_CloseSession(handle->session);
    if (chk_rv != CKR_OK) {
      return(chk_rv);
    }
  }

  chk_rv = handle->pkcs11->C_OpenSession(slot, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &tmp_session);

  if (chk_rv != CKR_OK) {
    handle->pkcs11->C_CloseSession(handle->session);

    return(chk_rv);
  }

  handle->session = tmp_session;
  handle->session_slot = slot;
  handle->session_active = 1;

  return(CKR_OK);
}

MODULE_SCOPE int tclpkcs11_close_session(struct tclpkcs11_handle *handle) {
  CK_RV chk_rv;

  if (handle->session_active) {
    handle->session_active = 0;
    chk_rv = handle->pkcs11->C_CloseSession(handle->session);

    if (chk_rv != CKR_OK) {
      return(chk_rv);
    }
  }

  return(CKR_OK);
}

/*
* Platform Specific Functions
*/
MODULE_SCOPE void *tclpkcs11_int_load_module(const char *pathname) {
  #if defined(HAVE_DLOPEN)
  return(dlopen(pathname, RTLD_NOW /*| RTLD_GLOBAL*/));
  /*	return(dlopen(pathname, RTLD_NOW | RTLD_GLOBAL));*/
  	
  #elif defined(HAVE_SHL_LOAD)
  return(shl_load(pathname, BIND_DEFERRED, 0L));
  #elif defined(_WIN32)
  /*MY*/
  char cp1251[2048];
  memset(cp1251, '\0', 2048);
  utf8_to_win1251((const char*) pathname, cp1251);

  return(LoadLibraryA(cp1251));
  #endif
  return(NULL);
}
MODULE_SCOPE void tclpkcs11_int_unload_module(void *handle) {
  #if defined(HAVE_DLOPEN)
  dlclose(handle);
  #elif defined(HAVE_SHL_LOAD)
  shl_unload(handle);
  #elif defined(_WIN32)
  FreeLibrary(handle);
  #endif
  return;
}
MODULE_SCOPE void *tclpkcs11_int_lookup_sym(void *handle, const char *sym) {
  #if defined(HAVE_DLOPEN)
  return(dlsym(handle, sym));
  #elif defined(HAVE_SHL_LOAD)
  void *retval;
  int shl_findsym_ret;

  shl_findsym_ret = shl_findsym(handle, sym, TYPE_PROCEDURE, &retval);
  if (shl_findsym_ret != 0) {
    return(NULL);
  }

  return(retval);
  #elif defined(_WIN32)
  return(GetProcAddress(handle, sym));
  #endif
  return(NULL);
}

/*
* Python Commands
*/
/**
 * Получение пути к библиотеки и возврат её handle.
 */
static PyObject *
pyp11_load_module (PyObject *self, PyObject *args) {
    extern struct tclpkcs11_interpdata *cd;
    struct tclpkcs11_interpdata *interpdata;
    struct tclpkcs11_handle *new_handle;
    const char *pathname = NULL;
    Py_ssize_t len_path = 0;
    void *handle;
    char tcl_handle[40];
    CK_C_GetFunctionList getFuncList;
    CK_FUNCTION_LIST_PTR pkcs11_function_list = NULL;
    CK_RV chk_rv;

    if (!cd) {
        PyErr_SetString(PyExc_TypeError, "pyp11_load_module: invalid clientdata");
	return NULL;
    }
    if (PyTuple_Size(args) != 1) {
        PyErr_SetString(PyExc_TypeError, "pyp11_load_module args error (count args != 1)");
	return NULL;
//Вопрос, что лучше
//	return Py_BuildValue("i", -1);
    }
    PyArg_ParseTuple(args, "s#", &pathname, &len_path);
    handle = tclpkcs11_int_load_module(pathname);

    if (!handle) {
        PyErr_SetString(PyExc_TypeError, "pyp11_load_module: unable to load");
	return NULL;
    }

    getFuncList = tclpkcs11_int_lookup_sym(handle, "C_GetFunctionList");
    if (!getFuncList) {
        PyErr_SetString(PyExc_TypeError, "pyp11_load_module: unable to locate C_GetFunctionList symbol in PKCS#11 module");
	return NULL;
    }

    chk_rv = getFuncList(&pkcs11_function_list);
    if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
    }

  if (!pkcs11_function_list) {
        PyErr_SetString(PyExc_TypeError, "pyp11_load_module: C_GetFunctionList returned invalid data");
	return NULL;
  }

  if (!pkcs11_function_list->C_Initialize) {
        PyErr_SetString(PyExc_TypeError, "pyp11_load_module: C_GetFunctionList returned incomplete data");
	return NULL;
  }
  chk_rv = pkcs11_function_list->C_Initialize(NULL);

  if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
    /* Attempt to unload the module */
	tclpkcs11_int_unload_module(handle);
	return NULL;
  }

  interpdata = (struct tclpkcs11_interpdata *) cd;
  sprintf(tcl_handle, "pkcs%lu", interpdata->handles_idx);
  (interpdata->handles_idx)++;
  /* Allocate the per-handle structure */
  new_handle = (struct tclpkcs11_handle *) malloc(sizeof(*new_handle));

  /* Initialize the per-handle structure */
  new_handle->base = handle;
  new_handle->pkcs11 = pkcs11_function_list;
  new_handle->session_active = 0;

//fprintf (stderr, "pyp11_load_module:new_handle=%lu, tcl_handle=%s,sizeof(handle)=%u\n", new_handle, tcl_handle, sizeof(new_handle));
  PyDict_SetItem(interpdata->handles, Py_BuildValue("s", tcl_handle), tclpkcs11_bytearray_to_string((unsigned char *)&new_handle, sizeof(new_handle)));
  return Py_BuildValue("s", tcl_handle);
}

static PyObject *
pyp11_unload_module(PyObject *self, PyObject *args) {
  extern struct tclpkcs11_interpdata *cd;
  struct tclpkcs11_interpdata *interpdata;
  struct tclpkcs11_handle *handle;
  char *tcl_handle;

  CK_RV chk_rv;
  PyObject *hh;

  if (!cd) {
        PyErr_SetString(PyExc_TypeError, "pyp11_unload_module: invalid hash_table");
	return NULL;
  }

  if (PyTuple_Size(args) != 1) {
        PyErr_SetString(PyExc_TypeError, "pyp11_unload_module args error (count args != 1)");
	return NULL;
  }

  PyArg_ParseTuple(args, "s", &tcl_handle);
//fprintf (stderr, "pyp11_unload_module: %s\n", tcl_handle);
  interpdata = (struct tclpkcs11_interpdata *) cd;
  hh =  PyDict_GetItemString(interpdata->handles, tcl_handle);
  if (hh == NULL) {
        PyErr_SetString(PyExc_TypeError, "pyp11_unload_module: invalid handle module)");
	return NULL;
  }
  tclpkcs11_string_to_bytearray(hh, (unsigned char *)&handle, sizeof(handle));
  if (!handle) {
        PyErr_SetString(PyExc_TypeError, "pyp11_unload_module: invalid 2 handle module)");
	return NULL;
  }

  // Log out of the PKCS11 module 
  handle->pkcs11->C_Logout(handle->session);
  // Close the session, cleaning up all the session objects 
  tclpkcs11_close_session(handle);

  // Ask the PKCS#11 Provider to terminate 
  chk_rv = handle->pkcs11->C_Finalize(NULL);
  if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
  }
  // Delete our hash entry 
//    table_remove(interpdata->handles, tcl_handle);//удалить
  PyDict_DelItemString(interpdata->handles, tcl_handle);

  // Attempt to unload the module 
  tclpkcs11_int_unload_module(handle->base);

  // Free our allocated handle 
  free((char *) handle);
    return Py_BuildValue("s", tcl_handle);
}

static PyObject *
pyp11_login(PyObject *self, PyObject *args) {
    extern struct tclpkcs11_interpdata *cd;
  struct tclpkcs11_interpdata *interpdata;
  struct tclpkcs11_handle *handle;
  char *tcl_handle;
  Py_ssize_t slotid_long = 0;
  char *password;
  int password_len;
  PyObject *hh;
//PyObject *args1, *args2, *args3;
PyObject *argspy[3];

  CK_SLOT_ID slotid;
  CK_RV chk_rv;
  if (!cd) {
        PyErr_SetString(PyExc_TypeError, "pyp11_login: invalid hash_table");
	return NULL;
  }

  if (PyTuple_Size(args) != 3) {
        PyErr_SetString(PyExc_TypeError, "pyp11_login args error (count args != 3)");
	return NULL;
  }

//  PyArg_ParseTuple(args, "sls", &tcl_handle, &slotid_long, &password);
  PyArg_ParseTuple(args, "OOO", &argspy[0], &argspy[1], &argspy[2]);
PyArg_Parse(argspy[0], "s", &tcl_handle);
PyArg_Parse(argspy[1], "l", &slotid_long);
PyArg_Parse(argspy[2], "s", &password);




  password_len = strlen(password);

  interpdata = (struct tclpkcs11_interpdata *) cd;
  hh =  PyDict_GetItemString(interpdata->handles, tcl_handle);
  if (hh == NULL) {
        PyErr_SetString(PyExc_TypeError, "pyp11_login: invalid handle module)");
	return NULL;
  }
  tclpkcs11_string_to_bytearray(hh, (unsigned char *)&handle, sizeof(handle));
  if (!handle) {
        PyErr_SetString(PyExc_TypeError, "pyp11_login: invalid handle module)");
	return NULL;
  }


  slotid = slotid_long;

  chk_rv = tclpkcs11_start_session(handle, slotid);
  if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
  }

  chk_rv = handle->pkcs11->C_Login(handle->session, CKU_USER, (CK_UTF8CHAR_PTR) password, password_len);
  switch (chk_rv) {
    case CKR_OK:
	break;
    case CKR_USER_ALREADY_LOGGED_IN:
        PyErr_SetString(PyExc_TypeError, "pyp11_login: CKR_USER_ALREADY_LOGGED_IN");
	return NULL;
      break;
    case CKR_PIN_INCORRECT:
        PyErr_SetString(PyExc_TypeError, "pyp11_login: CKR_PIN_INCORRECT");
	return NULL;
      break;
    default:
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
  }
    return Py_BuildValue("i", 1);
}

static PyObject *
pyp11_logout(PyObject *self, PyObject *args) {
    extern struct tclpkcs11_interpdata *cd;
  struct tclpkcs11_interpdata *interpdata;
  struct tclpkcs11_handle *handle;
  char *tcl_handle;
  Py_ssize_t slotid_long = 0;
  CK_SLOT_ID slotid;
  CK_RV chk_rv;
  PyObject *hh;

  if (!cd) {
        PyErr_SetString(PyExc_TypeError, "pyp11_login: invalid hash_table");
	return NULL;
  }

  if (PyTuple_Size(args) != 2) {
        PyErr_SetString(PyExc_TypeError, "pyp11_login args error (count args != 2)");
	return NULL;
  }

  PyArg_ParseTuple(args, "sl", &tcl_handle, &slotid_long);

  interpdata = (struct tclpkcs11_interpdata *) cd;
  hh =  PyDict_GetItemString(interpdata->handles, tcl_handle);
  if (hh == NULL) {
        PyErr_SetString(PyExc_TypeError, "pyp11_logout: invalid handle module)");
	return NULL;
  }
  tclpkcs11_string_to_bytearray(hh, (unsigned char *)&handle, sizeof(handle));

  if (!handle) {
        PyErr_SetString(PyExc_TypeError, "pyp11_login: invalid handle module)");
	return NULL;
  }

  slotid = slotid_long;

  chk_rv = tclpkcs11_start_session(handle, slotid);
  if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
  }

  chk_rv = handle->pkcs11->C_Logout(handle->session);
  if (chk_rv != CKR_OK) {
    if (chk_rv == CKR_DEVICE_REMOVED) {
      handle->session_active = 0;
      handle->pkcs11->C_CloseSession(handle->session);
    } else {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
    }
  }
    return Py_BuildValue("i", 1);
}

static PyObject *
pyp11_list_slots(PyObject *self, PyObject *args) {
    extern struct tclpkcs11_interpdata *cd;
  struct tclpkcs11_interpdata *interpdata;
  struct tclpkcs11_handle *handle;
  char *tcl_handle;
  PyObject *ret_list, *curr_item_list, *flags_list, *slot_desc, *token_desc;

  CK_SLOT_ID_PTR slots;
  CK_SLOT_INFO slotInfo;
  CK_TOKEN_INFO tokenInfo;
  CK_ULONG numSlots, currSlot;
  CK_RV chk_rv;
  PyObject *hh;

  if (!cd) {
        PyErr_SetString(PyExc_TypeError, "pyp11_list_slots: invalid hash_table");
	return NULL;
  }

  if (PyTuple_Size(args) != 1) {
        PyErr_SetString(PyExc_TypeError, "pyp11_list_slots args error (count args != 1)");
	return NULL;
  }

  PyArg_ParseTuple(args, "s", &tcl_handle);

  interpdata = (struct tclpkcs11_interpdata *) cd;
  hh =  PyDict_GetItemString(interpdata->handles, tcl_handle);
  if (hh == NULL) {
        PyErr_SetString(PyExc_TypeError, "pyp11_list_slots: invalid handle module)");
	return NULL;
  }
  tclpkcs11_string_to_bytearray(hh, (unsigned char *)&handle, sizeof(handle));

  if (!handle) {
        PyErr_SetString(PyExc_TypeError, "pyp11_list_slots: invalid handle module)");
	return NULL;
  }
  chk_rv = handle->pkcs11->C_GetSlotList(FALSE, NULL, &numSlots);
  if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
  }

  slots = (CK_SLOT_ID_PTR) malloc(sizeof(*slots) * numSlots);

  chk_rv = handle->pkcs11->C_GetSlotList(FALSE, slots, &numSlots);
  if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
  }
  ret_list = PyList_New(0);

  for (currSlot = 0; currSlot < numSlots; currSlot++) {
    chk_rv = handle->pkcs11->C_GetSlotInfo(slots[currSlot], &slotInfo);

    curr_item_list = PyList_New(0);
    PyList_Append(curr_item_list, PyLong_FromLong(slots[currSlot]));

    flags_list = PyList_New(0);

    if (chk_rv != CKR_OK) {
      /* Add an empty string as the token label */
	PyList_Append(curr_item_list, Py_BuildValue("s", ""));

      /* Add the list of existing flags (none) */
	PyList_Append(curr_item_list, flags_list);

      /* Add this item to the list */
	PyList_Append(ret_list, curr_item_list);

      continue;
    }

    slot_desc = NULL;
    token_desc = PyList_New(0);

    if ((slotInfo.flags & CKF_TOKEN_PRESENT) == CKF_TOKEN_PRESENT) {
	PyList_Append(flags_list, Py_BuildValue("s", "TOKEN_PRESENT"));

      chk_rv = handle->pkcs11->C_GetTokenInfo(slots[currSlot], &tokenInfo);

      if (chk_rv == CKR_OK) {
        /* Add the token label as the slot label */
        if (!slot_desc) {
            slot_desc = Py_BuildValue("s#", tokenInfo.label, 32);
	    PyList_Append(token_desc, Py_BuildValue("s#", tokenInfo.label, 32));
	    PyList_Append(token_desc, Py_BuildValue("s#", tokenInfo.manufacturerID, 32));
	    PyList_Append(token_desc, Py_BuildValue("s#", tokenInfo.model, 16));
	    PyList_Append(token_desc, Py_BuildValue("s#", tokenInfo.serialNumber, 16));
        }

        if ((tokenInfo.flags & CKF_RNG) == CKF_RNG) {
	    PyList_Append(flags_list, Py_BuildValue("s", "RNG"));
        }
        if ((tokenInfo.flags & CKF_WRITE_PROTECTED) == CKF_WRITE_PROTECTED) {
	    PyList_Append(flags_list, Py_BuildValue("s", "WRITE_PROTECTED"));
        }
        if ((tokenInfo.flags & CKF_LOGIN_REQUIRED) == CKF_LOGIN_REQUIRED) {
	    PyList_Append(flags_list, Py_BuildValue("s", "LOGIN_REQUIRED"));
        }
        if ((tokenInfo.flags & CKF_USER_PIN_INITIALIZED) == CKF_USER_PIN_INITIALIZED) {
	    PyList_Append(flags_list, Py_BuildValue("s", "USER_PIN_INITIALIZED"));
        }
        if ((tokenInfo.flags & CKF_RESTORE_KEY_NOT_NEEDED) == CKF_RESTORE_KEY_NOT_NEEDED) {
	    PyList_Append(flags_list, Py_BuildValue("s", "RESTORE_KEY_NOT_NEEDED"));
        }
        if ((tokenInfo.flags & CKF_CLOCK_ON_TOKEN) == CKF_CLOCK_ON_TOKEN) {
	    PyList_Append(flags_list, Py_BuildValue("s", "CLOCK_ON_TOKEN"));
        }
        if ((tokenInfo.flags & CKF_PROTECTED_AUTHENTICATION_PATH) == CKF_PROTECTED_AUTHENTICATION_PATH) {
	    PyList_Append(flags_list, Py_BuildValue("s", "PROTECTED_AUTHENTICATION_PATH"));
        }
        if ((tokenInfo.flags & CKF_DUAL_CRYPTO_OPERATIONS) == CKF_DUAL_CRYPTO_OPERATIONS) {
	    PyList_Append(flags_list, Py_BuildValue("s", "DUAL_CRYPTO_OPERATIONS"));
        }
        if ((tokenInfo.flags & CKF_TOKEN_INITIALIZED) == CKF_TOKEN_INITIALIZED) {
	    PyList_Append(flags_list, Py_BuildValue("s", "TOKEN_INITIALIZED"));
        }
        if ((tokenInfo.flags & CKF_SECONDARY_AUTHENTICATION) == CKF_SECONDARY_AUTHENTICATION) {
	    PyList_Append(flags_list, Py_BuildValue("s", "SECONDARY_AUTHENTICATION"));
        }
        if ((tokenInfo.flags & CKF_USER_PIN_COUNT_LOW) == CKF_USER_PIN_COUNT_LOW) {
	    PyList_Append(flags_list, Py_BuildValue("s", "USER_PIN_COUNT_LOW"));
        }
        if ((tokenInfo.flags & CKF_USER_PIN_FINAL_TRY) == CKF_USER_PIN_FINAL_TRY) {
	    PyList_Append(flags_list, Py_BuildValue("s", "USER_PIN_FINAL_TRY"));
        }
        if ((tokenInfo.flags & CKF_USER_PIN_LOCKED) == CKF_USER_PIN_LOCKED) {
	    PyList_Append(flags_list, Py_BuildValue("s", "USER_PIN_LOCKED"));
        }
        if ((tokenInfo.flags & CKF_USER_PIN_TO_BE_CHANGED) == CKF_USER_PIN_TO_BE_CHANGED) {
	    PyList_Append(flags_list, Py_BuildValue("s", "USER_PIN_TO_BE_CHANGED"));
        }
        if ((tokenInfo.flags & CKF_SO_PIN_COUNT_LOW) == CKF_SO_PIN_COUNT_LOW) {
	    PyList_Append(flags_list, Py_BuildValue("s", "SO_PIN_COUNT_LOW"));
        }
        if ((tokenInfo.flags & CKF_SO_PIN_FINAL_TRY) == CKF_SO_PIN_FINAL_TRY) {
	    PyList_Append(flags_list, Py_BuildValue("s", "SO_PIN_FINAL_TRY"));
        }
        if ((tokenInfo.flags & CKF_SO_PIN_LOCKED) == CKF_SO_PIN_LOCKED) {
	    PyList_Append(flags_list, Py_BuildValue("s", "SO_PIN_LOCKED"));
        }
        if ((tokenInfo.flags & CKF_SO_PIN_TO_BE_CHANGED) == CKF_SO_PIN_TO_BE_CHANGED) {
	    PyList_Append(flags_list, Py_BuildValue("s", "SO_PIN_TO_BE_CHANGED"));
        }
      }
    }

    /* Add additional slot flags */
    if ((slotInfo.flags & CKF_REMOVABLE_DEVICE) == CKF_REMOVABLE_DEVICE) {
	PyList_Append(flags_list, Py_BuildValue("s", "REMOVABLE_DEVICE"));
    }
    if ((slotInfo.flags & CKF_HW_SLOT) == CKF_HW_SLOT) {
	PyList_Append(flags_list, Py_BuildValue("s", "HW_SLOT"));
    }

    if (slot_desc) {
      /* If we found a more descriptive slot description, use it */
	PyList_Append(curr_item_list, slot_desc);
    } else {
      /* Add the slot description as the label for tokens with nothing in them */
	PyList_Append(curr_item_list, Py_BuildValue("s#", slotInfo.slotDescription, 32));
    }
    		
    PyList_Append(curr_item_list, flags_list);

    /*Descryption token*/
    PyList_Append(curr_item_list, token_desc);

    PyList_Append(ret_list, curr_item_list);
  }

    return ret_list;
}
static PyObject *
pyp11_listmechs(PyObject *self, PyObject *args) {
    extern struct tclpkcs11_interpdata *cd;
  struct tclpkcs11_interpdata *interpdata;
  struct tclpkcs11_handle *handle;
  char *tcl_handle;
//  long slotid_long;
  Py_ssize_t slotid_long = 0;
  CK_MECHANISM_TYPE_PTR MechanismList = NULL;  // Head to Mechanism list
  CK_ULONG       MechanismCount = 0;  // Number of supported mechanisms
  unsigned int   lcv2;           // Loop Control Variables
  CK_CHAR *name;
  CK_SLOT_ID slotid;
  PyObject *curr_item_list;
  char bufmech[256];
  CK_RV chk_rv;
  PyObject *hh;

  if (PyTuple_Size(args) != 2) {
        PyErr_SetString(PyExc_TypeError, "pyp11_listmechs args error (count args != 2)");
	return NULL;
  }

  PyArg_ParseTuple(args, "sl", &tcl_handle, &slotid_long);
//fprintf (stderr, "pyp11_listmech:tcl_handle=%s, slot=%ui\n", tcl_handle, slotid_long);

  interpdata = (struct tclpkcs11_interpdata *) cd;

  hh =  PyDict_GetItemString(interpdata->handles, tcl_handle);
  if (hh == NULL) {
        PyErr_SetString(PyExc_TypeError, "pyp11_listmechs: invalid handle module)");
	return NULL;
  }
  tclpkcs11_string_to_bytearray(hh, (unsigned char *)&handle, sizeof(handle));

//fprintf (stderr, "pyp11_listmech:handle=%lu, tcl_handle=%s, sizeof=%u\n", handle, tcl_handle, sizeof(handle));
  if (!handle) {
        PyErr_SetString(PyExc_TypeError, "pyp11_listmechs: invalid handle module)");
	return NULL;
  }

  slotid = slotid_long;
    chk_rv = handle->pkcs11->C_GetMechanismList(slotid, NULL, &MechanismCount);
    if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
    }

  /* Allocate enough memory to store all the supported mechanisms */
  MechanismList = (CK_MECHANISM_TYPE_PTR) malloc(MechanismCount *sizeof(CK_MECHANISM_TYPE));

  /* This time get the mechanism list */
  chk_rv = handle->pkcs11->C_GetMechanismList(slotid, MechanismList, &MechanismCount);
    if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
    }

  /* For each Mechanism in the List */
    curr_item_list = PyList_New(0);
  for (lcv2 = 0; lcv2 < MechanismCount; lcv2++){
    /* Get the Mechanism Info and display it */
    name = (CK_CHAR *)get_mechanism_name(MechanismList[lcv2]);
    if (name) {
      sprintf((char *)bufmech, "%s (0x%lX)", name, MechanismList[lcv2]);
    } else {
      sprintf((char *)bufmech, "0x%lX (0x%lX)", MechanismList[lcv2], MechanismList[lcv2]);
    }
    PyList_Append(curr_item_list, Py_BuildValue("s", bufmech));
  }
  /* Free the memory we allocated for the mechanism list */
  free (MechanismList);
    return (curr_item_list);
}
static char *class_name[] = {
  "CKO_DATA",
  "CKO_CERTIFICATE",
  "CKO_PUBLIC_KEY",
  "CKO_PRIVATE_KEY",
  "CKO_SECRET_KEY",
  "CKO_HW_FEATURE",
  "CKO_DOMAIN_PARAMETERS",
  "CKO_VENDOR_DEFINED"
};
static PyObject *
pyp11_list_objects(PyObject *self, PyObject *args) {
    extern struct tclpkcs11_interpdata *cd;
  static CK_BBOOL ltrue = CK_TRUE;
  struct tclpkcs11_interpdata *interpdata;
  struct tclpkcs11_handle *handle;
  char *tcl_handle;
  Py_ssize_t slotid_long = 0;
  int objc;

  PyObject *obj_hobj, *obj_label, *obj_id, *obj_object, *obj_value;
  PyObject *ret_list, *curr_item_list;
//Объекты для параметров ключа
  PyObject *obj_g10, *obj_g11, *obj_g28;

  unsigned char hexobj[40];
  PyObject *hstr;
  char *h_str;
  CK_SLOT_ID slotid;
  CK_OBJECT_HANDLE hObject;
  CK_ULONG ulObjectCount;
  char *objtype = NULL, *objdump = NULL;
  CK_UTF8CHAR label[2048];

  CK_OBJECT_CLASS oclass = 0;
  CK_BYTE ckaid[2048];
  CK_ATTRIBUTE *attr_find_obj;

  CK_ATTRIBUTE attr_find[] = {
    {CKA_TOKEN, &ltrue, sizeof(ltrue)},
  };
  CK_ATTRIBUTE attr_class[] = {
    {CKA_CLASS, NULL, 0},
  };
  CK_ATTRIBUTE attr_label[] = {
    {CKA_LABEL, NULL, 0},
  };
  CK_ATTRIBUTE attr_ckaid[] = {
    {CKA_ID, NULL, 0},
  };
  CK_ATTRIBUTE attr_ckavalue[] = {
    {CKA_VALUE, NULL, 0},
  };
  CK_ATTRIBUTE attr_pubkey[] = {
    {CKA_VALUE, NULL, 0},
    {CKA_GOSTR3410PARAMS, NULL, 0},
    {CKA_GOSTR3411PARAMS, NULL, 0},
    {CKA_GOST28147_PARAMS, NULL, 0},
  };
  int count;
  	
  CK_ATTRIBUTE attr_find_class[] = {
    {CKA_TOKEN, &ltrue, sizeof(ltrue)},
    {CKA_CLASS, &oclass, sizeof(oclass)},
  };

  CK_RV chk_rv;
  PyObject *hh;

  if (PyTuple_Size(args) < 2 || PyTuple_Size(args) > 4 ) {
        PyErr_SetString(PyExc_TypeError, "listobjects: args error (count args < 2 or > 4): listobjects handle slot [all|privkey|pubkey|cert|data] [value]");
	return NULL;
  }
  count = 1;
  attr_find_obj = attr_find;
  objc = PyTuple_Size(args);
//fprintf(stderr, "LISTOBJECTS objc=%i\n", objc);
  if (objc == 2) {
    PyArg_ParseTuple(args, "sl", &tcl_handle, &slotid_long);
  }
  if (objc == 3) {
    count = 2;
    PyArg_ParseTuple(args, "sls", &tcl_handle, &slotid_long, &objtype);
    if (strcmp(objtype, "all") == 0) {
      attr_find_obj = attr_find;
      count = 1;
    } else if (strcmp(objtype, "cert") == 0) {
      attr_find_obj = attr_find;
      oclass = CKO_CERTIFICATE;
      attr_find_obj = attr_find_class;
    } else if (strcmp(objtype, "pubkey") == 0) {
      attr_find_obj = attr_find;
      oclass = CKO_PUBLIC_KEY;
      attr_find_obj = attr_find_class;
    } else if (strcmp(objtype, "privkey") == 0) {
      attr_find_obj = attr_find;
      oclass = CKO_PRIVATE_KEY;
      attr_find_obj = attr_find_class;
    } else if (strcmp(objtype, "data") == 0) {
      attr_find_obj = attr_find;
      oclass = CKO_DATA;
      attr_find_obj = attr_find_class;
    } else {
        PyErr_SetString(PyExc_TypeError, "listobjects handle slot [all|privkey|pubkey|cert|data] [value]");
	return NULL;
    }
  }
  if (objc == 4) {
    count = 2;
    PyArg_ParseTuple(args, "slss", &tcl_handle, &slotid_long, &objtype, &objdump);
    if (strcmp(objdump, "value") != 0) {
        PyErr_SetString(PyExc_TypeError, "listobjects handle slot [all|privkey|pubkey|cert|data] [value]");
	return NULL;
    }
/*
//Печатать не печатать закрытый ключ
    if (strcmp(objtype, "privkey") == 0 && (strcmp(objdump, "value") == 0)) {
        PyErr_SetString(PyExc_TypeError, "listobjects: cannot read value private key");
	return NULL;
    }

    if (strcmp(objtype, "all") == 0 && (strcmp(objdump, "value") == 0)) {
        PyErr_SetString(PyExc_TypeError, "listobjects: cannot read value private key");
	return NULL;
    }
*/

    if (strcmp(objtype, "cert") == 0) {
//      attr_find_obj = attr_find;
      oclass = CKO_CERTIFICATE;
      attr_find_obj = attr_find_class;
    } else if (strcmp(objtype, "pubkey") == 0) {
//      attr_find_obj = attr_find;
      oclass = CKO_PUBLIC_KEY;
      attr_find_obj = attr_find_class;
    } else if (strcmp(objtype, "privkey") == 0) {
//      attr_find_obj = attr_find;
      oclass = CKO_PRIVATE_KEY;
      attr_find_obj = attr_find_class;
    } else if (strcmp(objtype, "data") == 0) {
//      attr_find_obj = attr_find;
      oclass = CKO_DATA;
      attr_find_obj = attr_find_class;
    } else if (strcmp(objtype, "all") == 0){
      count = 1;
    } else {
        PyErr_SetString(PyExc_TypeError, "listobjects handle slot [all|privkey|pubkey|cert|data] [value]");
	return NULL;
    }
  }

  interpdata = (struct tclpkcs11_interpdata *) cd;
  hh =  PyDict_GetItemString(interpdata->handles, tcl_handle);
  if (hh == NULL) {
        PyErr_SetString(PyExc_TypeError, "pyp11_listobjects: invalid handle module)");
	return NULL;
  }
  tclpkcs11_string_to_bytearray(hh, (unsigned char *)&handle, sizeof(handle));

  if (!handle) {
        PyErr_SetString(PyExc_TypeError, "pyp11_listobjects: invalid handle module)");
	return NULL;
  }
  slotid = slotid_long;

  chk_rv = tclpkcs11_start_session(handle, slotid);
  if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
  }

  chk_rv = handle->pkcs11->C_FindObjectsInit(handle->session,  attr_find_obj, count);
  if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
  }

  ret_list = PyList_New(0);
  while (1) {
    char *name = NULL;
    memset(label, 0, sizeof(label));
    attr_class[0].pValue = &oclass;
    attr_class[0].ulValueLen = sizeof(oclass);
    attr_label[0].pValue = label;
    attr_label[0].ulValueLen = sizeof(label);
    attr_ckaid[0].pValue = ckaid;
    attr_ckaid[0].ulValueLen = sizeof(ckaid);


    chk_rv = handle->pkcs11->C_FindObjects(handle->session, &hObject, 1, &ulObjectCount);
    if (chk_rv != CKR_OK) {
        handle->pkcs11->C_FindObjectsFinal(handle->session);
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
    }

    if (ulObjectCount == 0) {
      break;
    }

    if (ulObjectCount != 1) {
        handle->pkcs11->C_FindObjectsFinal(handle->session);
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
    }
    //////////////////////
    chk_rv = handle->pkcs11->C_GetAttributeValue(handle->session, hObject, attr_class, sizeof(attr_class)/sizeof(CK_ATTRIBUTE));
    if (chk_rv != CKR_OK) {
        handle->pkcs11->C_FindObjectsFinal(handle->session);
        PyErr_SetString(PyExc_TypeError, "pyp11_listobjects: C_GetAttributeValue CKA_CLASS for CKA_OBJECT_CLASS.");
	return NULL;
    }
    chk_rv = handle->pkcs11->C_GetAttributeValue(handle->session, hObject, attr_label, sizeof(attr_label)/sizeof(CK_ATTRIBUTE));
    if (chk_rv != CKR_OK) {
        handle->pkcs11->C_FindObjectsFinal(handle->session);
        PyErr_SetString(PyExc_TypeError, "pyp11_listobjects: C_GetAttributeValue CKA_LABEL for CKA_OBJECT_CLASS.");
	return NULL;
    }
    if (oclass >= CKO_VENDOR_DEFINED) {
      name = class_name[7];
    } else {
      name = class_name[oclass];
    }
    obj_object = Py_BuildValue("s#", name, strlen(name));

    hstr = tclpkcs11_bytearray_to_string((const unsigned char *)&hObject, sizeof(CK_OBJECT_HANDLE));
    strcpy((char *)hexobj, "hobj");
    PyArg_Parse(hstr, "s", &h_str);
    strcat((char *)hexobj, (char *)h_str);
    obj_hobj = Py_BuildValue("s", hexobj);

    //Восстановление HANDLE объекта в функциях, где они будут задействованы
    obj_label = Py_BuildValue("s#", (const char *)label, attr_label[0].ulValueLen);

    if (oclass == CKO_CERTIFICATE || oclass == CKO_PUBLIC_KEY || oclass == CKO_PRIVATE_KEY) {
      chk_rv = handle->pkcs11->C_GetAttributeValue(handle->session, hObject, attr_ckaid, sizeof(attr_ckaid)/sizeof(CK_ATTRIBUTE));
      if (chk_rv != CKR_OK) {
        handle->pkcs11->C_FindObjectsFinal(handle->session);
        PyErr_SetString(PyExc_TypeError, "pyp11_listobjects: C_GetAttributeValue CKA_ID for CKA_OBJECT_CLASS.");
	return NULL;
      }
      // Convert the ID into a readable string
      obj_id = tclpkcs11_bytearray_to_string(ckaid, attr_ckaid[0].ulValueLen);
    } else {
	obj_id = Py_BuildValue("s", "NONE");
    }
    if (objc == 4) {
        if (strcmp(objtype, "pubkey") != 0) {
    	    attr_ckavalue[0].pValue = NULL;
    	    attr_ckavalue[0].ulValueLen = 0;
    	    chk_rv = handle->pkcs11->C_GetAttributeValue(handle->session, hObject, attr_ckavalue, sizeof(attr_ckavalue)/sizeof(CK_ATTRIBUTE));
    	    if (chk_rv != CKR_OK) {
    		unsigned char erval[200];
    		handle->pkcs11->C_FindObjectsFinal(handle->session);
    		sprintf(erval, "pyp11_listobjects: C_GetAttributeValue CKA_VALUE for CKA_OBJECT_CLASS (%s)", objtype);
    		PyErr_SetString(PyExc_TypeError, erval);
		return NULL;
    	    }
    	    //fprintf(stderr, "LEN=%i\n", attr_ckavalue[0].ulValueLen);
    	    attr_ckavalue[0].pValue = malloc(attr_ckavalue[0].ulValueLen);
    	    chk_rv = handle->pkcs11->C_GetAttributeValue(handle->session, hObject, attr_ckavalue, sizeof(attr_ckavalue)/sizeof(CK_ATTRIBUTE));
    	    if (chk_rv != CKR_OK) {
    		handle->pkcs11->C_FindObjectsFinal(handle->session);
    		PyErr_SetString(PyExc_TypeError, "pyp11_listobjects: C_GetAttributeValue CKA_VALUE 1 for CKA_OBJECT_CLASS.");
		return NULL;
    	    }
    	    obj_value = tclpkcs11_bytearray_to_string(attr_ckavalue[0].pValue, attr_ckavalue[0].ulValueLen);
    	    free(attr_ckavalue[0].pValue);
        } else {
    	    CK_BYTE pkval[200];
    	    CK_BYTE atrg10[20];
    	    CK_BYTE atrg11[20];
    	    CK_BYTE atrg28[20];
	    attr_pubkey[0].pValue = NULL;
	    attr_pubkey[1].pValue = NULL;
	    attr_pubkey[2].pValue = NULL;
	    attr_pubkey[3].pValue = NULL;
    	    chk_rv = handle->pkcs11->C_GetAttributeValue(handle->session, hObject, attr_pubkey, sizeof(attr_pubkey)/sizeof(CK_ATTRIBUTE));
	    attr_pubkey[0].pValue = pkval;
	    attr_pubkey[1].pValue = atrg10;
	    attr_pubkey[2].pValue = atrg11;
	    attr_pubkey[3].pValue = atrg28;
    	    chk_rv = handle->pkcs11->C_GetAttributeValue(handle->session, hObject, attr_pubkey, sizeof(attr_pubkey)/sizeof(CK_ATTRIBUTE));
    	    if (chk_rv != CKR_OK) {
    		handle->pkcs11->C_FindObjectsFinal(handle->session);
    		PyErr_SetString(PyExc_TypeError, "pyp11_listobjects: C_GetAttributeValue CKA_VALUE, CKA_GOSTR3411PARAMS etc for PubKey.");
		return NULL;
    	    }
    	    obj_value = tclpkcs11_bytearray_to_string(attr_pubkey[0].pValue, attr_pubkey[0].ulValueLen);
    	    obj_g10 = tclpkcs11_bytearray_to_string(attr_pubkey[1].pValue, attr_pubkey[1].ulValueLen);
    	    obj_g11 = tclpkcs11_bytearray_to_string(attr_pubkey[2].pValue, attr_pubkey[2].ulValueLen);
	    if (attr_pubkey[3].ulValueLen > 0 )
    		obj_g28 = tclpkcs11_bytearray_to_string(attr_pubkey[3].pValue, attr_pubkey[3].ulValueLen);
    	    else 
    		obj_g28 = NULL;
        }
    }
    /* Create the current item list */
    curr_item_list = PyDict_New();
    PyDict_SetItem(curr_item_list, Py_BuildValue("s", "pkcs11_object"), obj_object);
    PyDict_SetItem(curr_item_list, Py_BuildValue("s", "pkcs11_handle"), obj_hobj);
    PyDict_SetItem(curr_item_list, Py_BuildValue("s", "pkcs11_label"), obj_label);
    if (oclass == CKO_CERTIFICATE || oclass == CKO_PUBLIC_KEY || oclass == CKO_PRIVATE_KEY) {
	PyDict_SetItem(curr_item_list, Py_BuildValue("s", "pkcs11_id"), obj_id);
    }
    if (objc == 4) {
	PyDict_SetItem(curr_item_list, Py_BuildValue("s", "value"), obj_value);
        if (strcmp(objtype, "pubkey") == 0) {
	    PyDict_SetItem(curr_item_list, Py_BuildValue("s", "gostr3410params"), obj_g10);
	    PyDict_SetItem(curr_item_list, Py_BuildValue("s", "gostr3411params"), obj_g11);
	    if (obj_g28 != NULL)
		PyDict_SetItem(curr_item_list, Py_BuildValue("s", "gost28147params"), obj_g28);
	}
    }
    /* Add the current item to the return value list */
    PyList_Append(ret_list, curr_item_list);
  }

  /* Terminate search */
  handle->pkcs11->C_FindObjectsFinal(handle->session);

  /* Return */
  return (ret_list);
}

static PyObject *
pyp11_list_certs_der(PyObject *self, PyObject *args) {
    extern struct tclpkcs11_interpdata *cd;
  struct tclpkcs11_interpdata *interpdata;
  struct tclpkcs11_handle *handle;
  char *tcl_handle;
  Py_ssize_t slotid_long = 0;
  PyObject *obj_label, *obj_id, *obj_cert_der;
  PyObject *ret_list, *curr_item_list;
  int type_cert;
  CK_SLOT_ID slotid;
  CK_OBJECT_HANDLE hObject;
  CK_ULONG ulObjectCount;
  static CK_OBJECT_CLASS     oclass_cert     = CKO_CERTIFICATE;
  CK_ATTRIBUTE cert_templ[] = {
    {CKA_CLASS, &oclass_cert, sizeof(oclass_cert)},
  };
  CK_ATTRIBUTE template[] = {
    {CKA_CLASS, NULL, 0},
    {CKA_LABEL, NULL, 0},
    {CKA_ID, NULL, 0},
    {CKA_VALUE, NULL, 0}
  }, *curr_attr;
  CK_ULONG curr_attr_idx;
  CK_OBJECT_CLASS *objectclass;
  CK_RV chk_rv;
  PyObject *hh;

    if (!cd) {
        PyErr_SetString(PyExc_TypeError, "pyp11_listcerts: invalid clientdata");
	return NULL;
    }

  if (PyTuple_Size(args) != 2) {
        PyErr_SetString(PyExc_TypeError, "pyp11_listcerts args error (count args != 2)");
	return NULL;
  }
  PyArg_ParseTuple(args, "sl", &tcl_handle, &slotid_long);

  interpdata = (struct tclpkcs11_interpdata *) cd;
  hh =  PyDict_GetItemString(interpdata->handles, tcl_handle);
  if (hh == NULL) {
        PyErr_SetString(PyExc_TypeError, "pyp11_listcerts: invalid handle module)");
	return NULL;
  }
  tclpkcs11_string_to_bytearray(hh, (unsigned char *)&handle, sizeof(handle));

  if (!handle) {
        PyErr_SetString(PyExc_TypeError, "pyp11_listcerts: 2 invalid handle module");
	return NULL;
  }

  slotid = slotid_long;
  chk_rv = tclpkcs11_start_session(handle, slotid);
  if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
  }

  chk_rv = handle->pkcs11->C_FindObjectsInit(handle->session,  cert_templ, sizeof(cert_templ) / sizeof(cert_templ[0]));
  if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
  }

    ret_list = PyList_New(0);

  while (1) {
    type_cert = 0;	
    chk_rv = handle->pkcs11->C_FindObjects(handle->session, &hObject, 1, &ulObjectCount);
    if (chk_rv != CKR_OK) {
      handle->pkcs11->C_FindObjectsFinal(handle->session);
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
    }
    if (ulObjectCount == 0) {
      break;
    }

    if (ulObjectCount != 1) {
      handle->pkcs11->C_FindObjectsFinal(handle->session);
        PyErr_SetString(PyExc_TypeError, "pyp11_listcerts: FindObjects() returned a weird number of objects.");
	return NULL;
    }

    for (curr_attr_idx = 0; curr_attr_idx < (sizeof(template) / sizeof(template[0])); curr_attr_idx++) {
      curr_attr = &template[curr_attr_idx];
      if (curr_attr->pValue) {
        free(curr_attr->pValue);
      }

      curr_attr->pValue = NULL;
      curr_attr->ulValueLen = 0;
    }

    /* Determine size of values to allocate */
    chk_rv = handle->pkcs11->C_GetAttributeValue(handle->session, hObject, template, sizeof(template) / sizeof(template[0]));
    if (chk_rv == CKR_ATTRIBUTE_TYPE_INVALID || chk_rv == CKR_ATTRIBUTE_SENSITIVE || chk_rv == CKR_BUFFER_TOO_SMALL) {
      chk_rv = CKR_OK;
    }

    if (chk_rv != CKR_OK) {
      /* Skip this object if we are not able to process it */
      continue;
    }

    /* Allocate values */
    for (curr_attr_idx = 0; curr_attr_idx < (sizeof(template) / sizeof(template[0])); curr_attr_idx++) {
      curr_attr = &template[curr_attr_idx];

      if (((CK_LONG) curr_attr->ulValueLen) != ((CK_LONG) -1)) {
        curr_attr->pValue = (void *) malloc(curr_attr->ulValueLen);
      }
    }

    /* Populate template values */
    chk_rv = handle->pkcs11->C_GetAttributeValue(handle->session, hObject, template, sizeof(template) / sizeof(template[0]));
    if (chk_rv != CKR_OK && chk_rv != CKR_ATTRIBUTE_SENSITIVE && chk_rv != CKR_ATTRIBUTE_TYPE_INVALID && chk_rv != CKR_BUFFER_TOO_SMALL) {
      /* Return an error if we are unable to process this entry due to unexpected errors */
      for (curr_attr_idx = 0; curr_attr_idx < (sizeof(template) / sizeof(template[0])); curr_attr_idx++) {
        curr_attr = &template[curr_attr_idx];
        if (curr_attr->pValue) {
          free(curr_attr->pValue);
        }
      }

      handle->pkcs11->C_FindObjectsFinal(handle->session);
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
    }

    /* Extract certificate data */
    obj_label = NULL;
    obj_id = NULL;
    obj_cert_der = NULL;
    objectclass = NULL;
    for (curr_attr_idx = 0; curr_attr_idx < (sizeof(template) / sizeof(template[0])); curr_attr_idx++) {
      curr_attr = &template[curr_attr_idx];
      if (!curr_attr->pValue) {
        continue;
      }

      switch (curr_attr->type) {
        case CKA_CLASS:
          objectclass = (CK_OBJECT_CLASS *) curr_attr->pValue;
          if (*objectclass != CKO_CERTIFICATE) {
            continue;
          }
          type_cert = 1;
          break;
        case CKA_LABEL:
	  obj_label = Py_BuildValue("s#", curr_attr->pValue, curr_attr->ulValueLen);
          break;
        case CKA_ID:
          /* Convert the ID into a readable string */
          obj_id = tclpkcs11_bytearray_to_string(curr_attr->pValue, curr_attr->ulValueLen);

          break;
        case CKA_VALUE:
          /*LISSI*/
          //fprintf (stderr, "tclpkcs11_list_certs_der: LEN_VALUE=%lu\n", curr_attr->ulValueLen);
          if (!objectclass) {
            break;
          }

          /* Convert the DER_CERT into a readable string */
          obj_cert_der = tclpkcs11_bytearray_to_string(curr_attr->pValue, curr_attr->ulValueLen);

          break;
      }

      free(curr_attr->pValue);
      curr_attr->pValue = NULL;
    }
    if (type_cert == 0) {
      continue;
    }

    /* Add this certificate data to return list, if all found */
    if (obj_label == NULL || obj_id == NULL || obj_cert_der == NULL) {
      continue;
    }

    /* Create the current item list */
    curr_item_list = PyDict_New();

    PyDict_SetItem(curr_item_list, Py_BuildValue("s", "pkcs11_id"), obj_id);

    PyDict_SetItem(curr_item_list, Py_BuildValue("s", "pkcs11_label"), obj_label);

    PyDict_SetItem(curr_item_list, Py_BuildValue("s", "cert_der"), obj_cert_der);

    /*
    * Override the "type" so that [array set] returns our new
    * type, but we can still parse through the list and figure
    * out the real subordinate type
    */
    PyDict_SetItem(curr_item_list, Py_BuildValue("s", "type"), Py_BuildValue("s", "pkcs11"));

    /* Add the current item to the return value list */
    PyList_Append(ret_list, curr_item_list);
  }

  /* Terminate search */
  handle->pkcs11->C_FindObjectsFinal(handle->session);
  /* Return */
    return (ret_list);
}

static PyObject *
pyp11_digest(PyObject *self, PyObject *args) {
    extern struct tclpkcs11_interpdata *cd;
  struct tclpkcs11_interpdata *interpdata;
  struct tclpkcs11_handle *handle;
  unsigned char *input, resultbuf[1024];
  char *algohash;
  int input_len;
  CK_ULONG resultbuf_len;
  char *tcl_handle = NULL;
  PyObject *tcl_result;
  Py_ssize_t slotid_long = 0;
  CK_SLOT_ID slotid;
  CK_MECHANISM     mechanism_desc = { CKM_GOSTR3411, NULL, 0 };
  CK_MECHANISM     mechanism_desc_512 = { CKM_GOSTR3411_12_512, NULL, 0 };
  CK_MECHANISM     mechanism_desc_256 = { CKM_GOSTR3411_12_256, NULL, 0 };
  CK_MECHANISM     mechanism_desc_sha1 = { CKM_SHA_1, NULL, 0 };
  CK_MECHANISM_PTR mechanism;
  CK_RV chk_rv;
  PyObject *hh;

  if (!cd) {
        PyErr_SetString(PyExc_TypeError, "pyp11_digest: invalid hash_table");
	return NULL;
  }

  if (PyTuple_Size(args) != 4) {
        PyErr_SetString(PyExc_TypeError, "pyp11_digest args error (count args != 3): digest handle slot <algo digest> <content>");
	return NULL;
  }

  PyArg_ParseTuple(args, "slsz#", &tcl_handle, &slotid_long, &algohash, &input, &input_len);
//fprintf (stderr, "pyp11_digest: handle=%s, slot=%u, algo=%s, input=%s, len=%i\n", tcl_handle, slotid_long, algohash, input, input_len);

  interpdata = (struct tclpkcs11_interpdata *) cd;
  hh =  PyDict_GetItemString(interpdata->handles, tcl_handle);
  if (hh == NULL) {
        PyErr_SetString(PyExc_TypeError, "pyp11_digest: invalid handle module)");
	return NULL;
  }
  tclpkcs11_string_to_bytearray(hh, (unsigned char *)&handle, sizeof(handle));

  if (!handle) {
        PyErr_SetString(PyExc_TypeError, "pyp11_digest: invalid handle module");
	return NULL;
  }

  slotid = slotid_long;

  chk_rv = tclpkcs11_start_session(handle, slotid);
  if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
  }
//======================
  //fprintf(stderr, "tclpkcs11_perform_pki_digest objc=%d, algohash=%s\n",  objc,algohash);
  //fprintf(stderr, "tclpkcs11_perform_pki_digest=%i, objc=%s\n", input_len, input);
  if (!memcmp("stribog256", algohash, 10)) {
    mechanism = &mechanism_desc_256;
  } else if (!memcmp("stribog512", algohash, 10)) {
    mechanism = &mechanism_desc_512;
  } else if (!memcmp("gostr3411", algohash, 9)) {
    mechanism = &mechanism_desc;
  } else if (!memcmp("sha1", algohash, 4)) {
    mechanism = &mechanism_desc_sha1;
  } else {
        PyErr_SetString(PyExc_TypeError, "\"pyp11_digest <handle> <slot> stribog256|stribog512|gostr3411|sha1 <content>\" - bad digest");
	return NULL;
  }
  slotid = slotid_long;

  //fprintf(stderr,"tclpkcs11_perform_pki_digest Digest slotid=%lu\n", slotid);
  chk_rv = tclpkcs11_start_session(handle, slotid);
  if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
  }
  //fprintf(stderr,"tclpkcs11_perform_pki_digest SESSION OK\n");
  chk_rv = handle->pkcs11->C_DigestInit(handle->session, mechanism);
  if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
  }
  	
  resultbuf_len = 128;
  chk_rv = handle->pkcs11->C_Digest(handle->session, input, input_len, resultbuf, &resultbuf_len);
  if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
  }

  // Convert the ID into a readable string 
  tcl_result = tclpkcs11_bytearray_to_string(resultbuf, resultbuf_len);

  return (tcl_result);
}
static PyObject *
pyp11_keypair(PyObject *self, PyObject *args) {
/*Usage keypair <handle> <slot> <type key> <par key/sign> [<cka_label>] */
    extern struct tclpkcs11_interpdata *cd;
  struct tclpkcs11_interpdata *interpdata;
  struct tclpkcs11_handle *handle;
  char *algokey, *param, *label;
  unsigned char *asn, *asn1, *asn2;
  CK_ULONG *ulattr;
  char *tcl_handle = NULL;
  Py_ssize_t slotid_long = 0;
  CK_SLOT_ID slotid;
  CK_MECHANISM     mechanism_desc_512 = { CKM_GOSTR3410_512_KEY_PAIR_GEN, NULL, 0 };
  CK_MECHANISM     mechanism_desc_256 = { CKM_GOSTR3410_KEY_PAIR_GEN, NULL, 0 };
  CK_MECHANISM_PTR mechanism_gen;
  CK_RV chk_rv;
  CK_ULONG curr_attr_idx;
  PyObject *obj_label, *obj_id, *obj_key_der, *obj_gostr3411 = NULL, *obj_gostr3410 = NULL, *obj_key_type = NULL, *obj_key_type_oid = NULL;
  PyObject *hobj_pub, *hobj_priv;

  PyObject *obj_gost28147;
  CK_OBJECT_CLASS *objectclass;
  PyObject *curr_item_list;
  static CK_BBOOL        ltrue       = CK_TRUE;
//  static CK_BBOOL        lfalse       = CK_FALSE;
  static CK_OBJECT_CLASS oclass_pub  = CKO_PUBLIC_KEY;
  static CK_OBJECT_CLASS oclass_priv = CKO_PRIVATE_KEY;
  static CK_BYTE         gost28147params_Z[] = {
    0x06, 0x09, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x05, 0x01, 0x01
  };
/*
  static CK_BYTE         gost28147params[] = {
    0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1f, 0x01
  };
*/
/*
// GOST R 34.10-2001 CryptoPro parameter set OIDs
//1.2.643.2.2.35.1 -  1.2.643.2.2.35.3 A-C   from CryptoPro
  static CK_BYTE ecc_A_oid[]    = {0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01};
  static CK_BYTE ecc_B_oid[]    = {0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x02};
  static CK_BYTE ecc_C_oid[]    = {0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x03};
//1.2.643.2.2.36.0 -  1.2.643.2.2.36.1 XA-XB   from CryptoPro
  static CK_BYTE ecc_XchA_oid[] = {0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x24, 0x00};
  static CK_BYTE ecc_XchB_oid[] = {0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x24, 0x01};
// GOST R 34.10-2012-256 Tk-26 parameter set OIDs
//1.2.643.7.1.2.1.1.1 -  1.2.643.7.1.2.1.1.4   from tc-26
  static CK_BYTE tc26_A_oid[]    = {0x06, 0x09, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x01, 0x01};
  static CK_BYTE tc26_B_oid[]    = {0x06, 0x09, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x01, 0x02};
  static CK_BYTE tc26_C_oid[]    = {0x06, 0x09, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x01, 0x03};
  static CK_BYTE tc26_D_oid[]    = {0x06, 0x09, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x01, 0x04};
//Parameters for GOST-2012-512/
//1.2.643.7.1.2.1.2.1 -  1.2.643.7.1.2.1.2.3   from tc-26
  static CK_BYTE tc26_decc_A_der_oid[] = {0x06, 0x09, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x02, 0x01};
  static CK_BYTE tc26_decc_B_der_oid[] = {0x06, 0x09, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x02, 0x02};
  static CK_BYTE tc26_decc_C_der_oid[] = {0x06, 0x09, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x02, 0x03};
*/

  /*GOST R 34.11-94*/
  static CK_BYTE gost3411_94[] = {0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1e, 0x01};
  /*LISSI 2012*/
  /*1.2.643.7.1.1.2.2	id-tc26-gost3411-2012-256	алгоритм хэширования ГОСТ Р 34.11-2012 с длиной 256*/
  static CK_BYTE gost3411_2012_256[] = {0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02};
  /*1.2.643.7.1.1.2.3	id-tc26-gost3411-2012-512	алгоритм хэширования ГОСТ Р 34.11-2012 с длиной 512*/
  static CK_BYTE gost3411_2012_512[] = {0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x03};

  CK_OBJECT_HANDLE       pub_key            = CK_INVALID_HANDLE;
  CK_OBJECT_HANDLE       priv_key           = CK_INVALID_HANDLE;

  CK_ATTRIBUTE       pub_template[] = {
    { CKA_CLASS,           &oclass_pub, sizeof(oclass_pub) },
    { CKA_TOKEN,           &ltrue,      sizeof(ltrue)      },
    { CKA_GOSTR3410PARAMS,	NULL, 0 },
    { CKA_GOSTR3411PARAMS,  NULL, 0 },
    { CKA_LABEL, NULL, 0},
    { CKA_VERIFY,          &ltrue,      sizeof(CK_BBOOL)   },
    { CKA_WRAP,          &ltrue,      sizeof(CK_BBOOL)   },
    { CKA_GOST28147PARAMS, gost28147params_Z, sizeof(gost28147params_Z) },
  };
  CK_ATTRIBUTE       priv_template[] = {
    { CKA_CLASS,   &oclass_priv, sizeof(oclass_priv) },
    { CKA_TOKEN,   &ltrue,       sizeof(ltrue)       },
    { CKA_PRIVATE, &ltrue,       sizeof(ltrue)       },
    { CKA_UNWRAP,    &ltrue,       sizeof(CK_BBOOL)    },
    { CKA_LABEL, NULL, 0},
    { CKA_SIGN,    &ltrue,       sizeof(CK_BBOOL)    },
    { CKA_DERIVE,    &ltrue,       sizeof(CK_BBOOL)    },
  };

  CK_ATTRIBUTE templ_pk[] = {
    {CKA_CLASS, NULL, 0},
    {CKA_LABEL, NULL, 0},
    {CKA_ID, NULL, 0},
    {CKA_VALUE, NULL, 0},
    {CKA_GOSTR3410PARAMS, NULL, 0},
    {CKA_GOSTR3411PARAMS, NULL, 0},
    {CKA_GOST28147PARAMS, NULL, 0},
    {CKA_KEY_TYPE, NULL, 0}
  }, *curr_attr;
  int tcl_rv;
  unsigned char *hexoid = NULL;
  size_t lenhex;
  int objc;
  unsigned char hexobj[40];
  PyObject *hstr;
  char *h_str;
  char *h_str1;
  PyObject *hh;

  if (!cd) {
        PyErr_SetString(PyExc_TypeError, "pyp11_keypair: invalid hash_table");
	return NULL;
  }
  objc = PyTuple_Size(args);
  if (objc != 4  && objc != 5) {
        PyErr_SetString(PyExc_TypeError, "pyp11_keypair args error (count args != 4 and !=5): keypair handle slot <algo key> <par key> [<cka_label>]");
	return NULL;
//fprintf (stderr, "pyp11_keypair: handle=%s, slot=%u, algokey=%s, param=%s\n", tcl_handle, slotid_long, algokey, param);
  }
  if (objc == 4)
        PyArg_ParseTuple(args, "slss", &tcl_handle, &slotid_long, &algokey, &param);
  else {
        PyArg_ParseTuple(args, "slsss", &tcl_handle, &slotid_long, &algokey, &param, &label);
	pub_template[4].pValue = label;
	pub_template[4].ulValueLen = strlen(label);
	priv_template[4].pValue = label;
	priv_template[4].ulValueLen = strlen(label);
//fprintf (stderr, "pyp11_keypair: handle=%s, slot=%u, algokey=%s, param=%s, label=%s\n", tcl_handle, slotid_long, algokey, param, label);
  }

  interpdata = (struct tclpkcs11_interpdata *) cd;
  hh =  PyDict_GetItemString(interpdata->handles, tcl_handle);
  if (hh == NULL) {
        PyErr_SetString(PyExc_TypeError, "pyp11_keypair: invalid handle module)");
	return NULL;
  }
  tclpkcs11_string_to_bytearray(hh, (unsigned char *)&handle, sizeof(handle));

  if (!handle) {
        PyErr_SetString(PyExc_TypeError, "pyp11_keypair: invalid handle module");
	return NULL;
  }

  slotid = slotid_long;

  chk_rv = tclpkcs11_start_session(handle, slotid);
  if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
  }
  tcl_rv = oid_from_str(param, &hexoid, &lenhex);
  if (tcl_rv == -1) {
        PyErr_SetString(PyExc_TypeError, "pyp11_keypair handle slot g12_256|g12_512 oid_param_sign [cka_label]: bad parameter for key");
	return NULL;
  }
  pub_template[2].pValue = hexoid;
  pub_template[2].ulValueLen = lenhex;
  
  if (!memcmp("g12_256", algokey, 7)) {
    mechanism_gen = &mechanism_desc_256;
    pub_template[3].pValue =gost3411_2012_256;
    pub_template[3].ulValueLen = sizeof(gost3411_2012_256);
  } else if (!memcmp("g12_512", algokey, 7)) {
    mechanism_gen = &mechanism_desc_512;
    pub_template[3].pValue =gost3411_2012_512;
    pub_template[3].ulValueLen = sizeof(gost3411_2012_512);
  } else if (!memcmp("gost2001", algokey, 8)) {
    mechanism_gen = &mechanism_desc_256;
    pub_template[3].pValue =gost3411_94;
    pub_template[3].ulValueLen = sizeof(gost3411_94);
  } else {
        PyErr_SetString(PyExc_TypeError, "pyp11_keypair handle slot g12_256|g12_512 oid_param_sign [cka_label]: bad type key");
	return NULL;
  }

  //fprintf(stderr,"tclpkcs11_perform_pki_keypair SESSION OK\n");
  chk_rv = handle->pkcs11->C_GenerateKeyPair(handle->session, mechanism_gen,
  pub_template, sizeof(pub_template) / sizeof(CK_ATTRIBUTE),
  priv_template, sizeof(priv_template) / sizeof(CK_ATTRIBUTE), &pub_key, &priv_key);
  if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
  }
    hstr = tclpkcs11_bytearray_to_string((const unsigned char *)&pub_key, sizeof(CK_OBJECT_HANDLE));
    strcpy((char *)hexobj, "hobj");
    PyArg_Parse(hstr, "s", &h_str);
    strcat((char *)hexobj, h_str);
//fprintf(stderr, "HOBJ_PUB=%s\n", hexobj);
    hobj_pub = Py_BuildValue("s", hexobj);
    hstr = tclpkcs11_bytearray_to_string((const unsigned char *)&priv_key, sizeof(CK_OBJECT_HANDLE));
    strcpy((char *)hexobj, "hobj");
    PyArg_Parse(hstr, "s", &h_str);
    strcat((char *)hexobj, h_str);
//fprintf(stderr, "HOBJ_PRIV=%s\n", hexobj);
    hobj_priv = Py_BuildValue("s", hexobj);

  ////// Очищаем templ_pk ////////////////////////////
  for (curr_attr_idx = 0; curr_attr_idx < (sizeof(templ_pk) / sizeof(templ_pk[0])); curr_attr_idx++) {
    curr_attr = &templ_pk[curr_attr_idx];
    if (curr_attr->pValue) {
      free(curr_attr->pValue);
    }

    curr_attr->pValue = NULL;
    curr_attr->ulValueLen = 0;
  }

  /* Determine size of values to allocate */
  chk_rv = handle->pkcs11->C_GetAttributeValue(handle->session, pub_key, templ_pk, sizeof(templ_pk) / sizeof(templ_pk[0]));
  if (chk_rv == CKR_ATTRIBUTE_TYPE_INVALID || chk_rv == CKR_ATTRIBUTE_SENSITIVE || chk_rv == CKR_BUFFER_TOO_SMALL) {
    chk_rv = CKR_OK;
  }

  if (chk_rv != CKR_OK) {
    /* Skip this object if we are not able to process it */
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
  }

  /* Allocate values */
  for (curr_attr_idx = 0; curr_attr_idx < (sizeof(templ_pk) / sizeof(templ_pk[0])); curr_attr_idx++) {
    curr_attr = &templ_pk[curr_attr_idx];

    if (((CK_LONG) curr_attr->ulValueLen) != ((CK_LONG) -1)) {
      curr_attr->pValue = (void *) malloc(curr_attr->ulValueLen);
    }
  }

  /* Populate template values */
  chk_rv = handle->pkcs11->C_GetAttributeValue(handle->session, pub_key, templ_pk, sizeof(templ_pk) / sizeof(templ_pk[0]));
  if (chk_rv != CKR_OK && chk_rv != CKR_ATTRIBUTE_SENSITIVE && chk_rv != CKR_ATTRIBUTE_TYPE_INVALID && chk_rv != CKR_BUFFER_TOO_SMALL) {
    /* Return an error if we are unable to process this entry due to unexpected errors */
    for (curr_attr_idx = 0; curr_attr_idx < (sizeof(templ_pk) / sizeof(templ_pk[0])); curr_attr_idx++) {
      curr_attr = &templ_pk[curr_attr_idx];
      if (curr_attr->pValue) {
        free(curr_attr->pValue);
      }
    }
    handle->pkcs11->C_FindObjectsFinal(handle->session);
    PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
    return NULL;
  }

  //////////////////////////////////////////////
  /* Extract publickey data */
  obj_label = NULL;
  obj_id = NULL;
  obj_key_der = NULL;
  objectclass = NULL;
  for (curr_attr_idx = 0; curr_attr_idx < (sizeof(templ_pk) / sizeof(templ_pk[0])); curr_attr_idx++) {
    curr_attr = &templ_pk[curr_attr_idx];

    if (!curr_attr->pValue) {
      continue;
    }

    switch (curr_attr->type) {
      case CKA_CLASS:
        objectclass = (CK_OBJECT_CLASS *) curr_attr->pValue;
        if (*objectclass != CKO_PUBLIC_KEY) {
          continue;
        }
        break;
      case CKA_LABEL:
	obj_label = Py_BuildValue("s#",curr_attr->pValue, curr_attr->ulValueLen);
        break;
      case CKA_ID:
        /* Convert the ID into a readable string */
        obj_id = tclpkcs11_bytearray_to_string(curr_attr->pValue, curr_attr->ulValueLen);
//	if (strlen(obj_id) == 0) {
	if (curr_attr->ulValueLen == 0) {
	    CK_ATTRIBUTE      attr_update[] = {
		{ CKA_ID, NULL, 0     },
	    };
//Calculare CKA_ID for GOST
	    CK_MECHANISM     mechanism_desc_sha1 = { CKM_SHA_1, NULL, 0 };
	    CK_MECHANISM_PTR mechanism;
	    int idckalen = 0;
	    unsigned char os64[] = { 0x04, 0x40 };
	    unsigned char os128[] = { 0x04, 0x81, 0x80 };
	    unsigned char osfull[132];
	    int oslen;
	    if (templ_pk[3].ulValueLen == 64) {
		oslen = 2;
		memmove(&osfull[0], os64, 2);
	    } else if (templ_pk[3].ulValueLen == 128) {
		oslen = 3;
		memmove(&osfull[0], os128, 3);
	    } else {
		oslen = 0;
//        	fprintf(stderr, "tclpkcs11_perform_pki_keypair : %i\n", templ_pk[3].ulValueLen);
//		return(TCL_ERROR);
    		PyErr_SetString(PyExc_TypeError, "pyp11_keypair handle slot g12_256|g12_512 oid_param_sign [cka_label]: bad length key");
		return NULL;
	    }
	    memmove(&osfull[oslen], templ_pk[3].pValue,templ_pk[3].ulValueLen);
	    attr_update[0].pValue = malloc(20);
	    attr_update[0].ulValueLen = 20;
	    oslen += templ_pk[3].ulValueLen;
	    
	    mechanism = &mechanism_desc_sha1;
	    chk_rv = handle->pkcs11->C_DigestInit(handle->session, mechanism);
	    if (chk_rv != CKR_OK) {
    		free(attr_update[0].pValue);
		PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
		return NULL;
	    }
	    idckalen = 20;
	    chk_rv = handle->pkcs11->C_Digest(handle->session, (CK_BYTE *)osfull, oslen, attr_update[0].pValue, (CK_ULONG_PTR)&idckalen);
	    if (chk_rv != CKR_OK) {
    		free(attr_update[0].pValue);
		PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
		return NULL;
	    }
	    chk_rv = handle->pkcs11->C_SetAttributeValue(handle->session, pub_key, attr_update,1);
	    chk_rv = handle->pkcs11->C_SetAttributeValue(handle->session, priv_key, attr_update,1);

    	    obj_id = tclpkcs11_bytearray_to_string(attr_update[0].pValue, attr_update[0].ulValueLen);
    	    free(attr_update[0].pValue);
	}

        break;
      case CKA_VALUE:
        if (!objectclass) {
          break;
        }
        /* Convert the DER_KEY into a readable string */
        obj_key_der = tclpkcs11_bytearray_to_string(curr_attr->pValue, curr_attr->ulValueLen);

        break;
      case CKA_GOSTR3411PARAMS:
        obj_gostr3411 = tclpkcs11_bytearray_to_string(curr_attr->pValue, curr_attr->ulValueLen);
        break;
      case CKA_GOSTR3410PARAMS:
        obj_gostr3410 = tclpkcs11_bytearray_to_string(curr_attr->pValue, curr_attr->ulValueLen);
        break;
      case CKA_GOST28147PARAMS:
        obj_gost28147 = tclpkcs11_bytearray_to_string(curr_attr->pValue, curr_attr->ulValueLen);
        break;
      case CKA_KEY_TYPE:
        ulattr = curr_attr->pValue;
        if (*ulattr == CKK_GOSTR3410) {
	  PyArg_Parse(obj_gostr3411, "s", &h_str);
//fprintf(stderr, "pyp11_keypair CKK_GOSTR3411=%s\n", h_str);
          if (!strstr(h_str, "06082a850307")) {
	    obj_key_type_oid = Py_BuildValue("s", "1 2 643 2 2 19");
            obj_key_type = tclpkcs11_bytearray_to_string((const unsigned char *)"\x06\x06\x2a\x85\x03\x02\x02\x13", 8);
          } else {
	    obj_key_type_oid = Py_BuildValue("s", "1 2 643 7 1 1 1 1");
            obj_key_type = tclpkcs11_bytearray_to_string((const unsigned char *)"\x06\x08\x2a\x85\x03\x07\x01\x01\x01\x01", 10);
          }
          //fprintf(stderr, "tclpkcs11_perform_pki_keypair CKK_GOSTR3410\n");
        } else if (*ulattr == CKK_GOSTR3410_512) {
	    obj_key_type_oid = Py_BuildValue("s", "1 2 643 7 1 1 1 2");
            obj_key_type = tclpkcs11_bytearray_to_string((const unsigned char *)"\x06\x08\x2a\x85\x03\x07\x01\x01\x01\x02", 10);
          //fprintf(stderr, "tclpkcs11_perform_pki_keypair CKK_GOSTR3410_512=%s\n", Tcl_GetString(obj_gostr3411));
        } else {
    	    PyErr_SetString(PyExc_TypeError, "pyp11.keypair CKK_GOSTR ERROR");
	    return NULL;
        }
        break;
    }

    free(curr_attr->pValue);
    curr_attr->pValue = NULL;
  }

  /* Add this certificate data to return list, if all found */
  if (obj_label == NULL || obj_id == NULL || obj_key_der == NULL) {
    //			continue;
  }
  if (obj_key_type == NULL || obj_key_type_oid == NULL || obj_gostr3410 == NULL) {
    	    PyErr_SetString(PyExc_TypeError, "pyp11.keypair: total error");
	    return NULL;
  }

  /* Create the current item list */
    curr_item_list = PyDict_New();
//    PyDict_SetItem(curr_item_list, Py_BuildValue("s", "pkcs11_handle"), Py_BuildValue("s", tcl_handle));
//    PyDict_SetItem(curr_item_list, Py_BuildValue("s", "pkcs11_slotid"), Py_BuildValue("l", slotid_long));
    PyDict_SetItem(curr_item_list, Py_BuildValue("s", "hobj_pubkey"), hobj_pub);
    PyDict_SetItem(curr_item_list, Py_BuildValue("s", "hobj_privkey"), hobj_priv);
    PyDict_SetItem(curr_item_list, Py_BuildValue("s", "pkcs11_id"), obj_id);
    PyDict_SetItem(curr_item_list, Py_BuildValue("s", "pkcs11_label"), obj_label);

//=========
  ////pubkeyinfo
  PyArg_Parse(obj_key_der, "s", &h_str);
  asn = wrap_for_asn1('\x03',  "00", (asn1 = wrap_for_asn1('\x04',"", (unsigned char *)h_str)));

  free(asn1);

  PyArg_Parse(obj_gostr3410, "s", &h_str);
  PyArg_Parse(obj_gostr3411, "s", &h_str1);
  asn1 = wrap_for_asn1('\x30', (char*)h_str, (unsigned char*)h_str1);


  PyArg_Parse(obj_key_type, "s", &h_str);
  asn2 = malloc(strlen((const char*)h_str) + strlen((const char*)asn1) + 1);
  strcpy((char*)asn2, (const char*)h_str);
  strcat((char*)asn2, (const char*)asn1);
  free(asn1);
  asn1 = wrap_for_asn1('\x30',  "", asn2);
  free(asn2);
  asn2 = malloc(strlen((const char*)asn) + strlen((const char*)asn1) + 1);
  strcpy((char*)asn2, (const char*)asn1);
  strcat((char*)asn2, (const char*)asn);
  free(asn1); free(asn);

    PyDict_SetItem(curr_item_list, Py_BuildValue("s", "pubkey"), obj_key_der);

    PyDict_SetItem(curr_item_list, Py_BuildValue("s", "pubkey_algo"), obj_key_type_oid);

    PyDict_SetItem(curr_item_list, Py_BuildValue("s", "pubkeyinfo"), Py_BuildValue("s", asn2));
  free(asn2);
  /*
  * Override the "type" so that [array set] returns our new
  * type, but we can still parse through the list and figure
  * out the real subordinate type
  */
    PyDict_SetItem(curr_item_list, Py_BuildValue("s", "type"), Py_BuildValue("s", "pkcs11"));

  /* Add the current item to the return value list */
  /* Return */
  return (curr_item_list);
}
static PyObject *
pyp11_importcert(PyObject *self, PyObject *args) {
/*Usage importcert <handle> <slot> <cert_der to hex> => pkcs11_id to hex */
    extern struct tclpkcs11_interpdata *cd;
  static CK_BBOOL        ltrue       = CK_TRUE;
  static CK_BBOOL        lfalse      = CK_FALSE;
  CK_BYTE *cert_der;
  CK_OBJECT_HANDLE pub_key = CK_INVALID_HANDLE;

  static CK_OBJECT_CLASS     oclass_cert     = CKO_CERTIFICATE;
  static CK_CERTIFICATE_TYPE ocert_type      = CKC_X_509;
  static CK_OBJECT_CLASS oclass_pub  = CKO_PUBLIC_KEY;
  static CK_OBJECT_CLASS oclass_priv = CKO_PRIVATE_KEY;
  long serial_num = 0;
  CK_MECHANISM     mechanism_desc_sha1 = { CKM_SHA_1, NULL, 0 };
  CK_MECHANISM_PTR mechanism;
  PyObject *tcl_result;

  CK_ATTRIBUTE           templ_certimport[] = {
    { CKA_CLASS,                &oclass_cert,     sizeof(oclass_cert)},
    { CKA_CERTIFICATE_TYPE,     &ocert_type,      sizeof(ocert_type)},
    { CKA_ID,		    NULL,			0  },
    { CKA_TOKEN,                &ltrue,           sizeof(ltrue)},
    { CKA_PRIVATE,              &lfalse,          sizeof(lfalse)},
    { CKA_LABEL,                NULL,			0 },	// 5
    { CKA_SUBJECT,              NULL,			0 },	// 6
    { CKA_ISSUER,               NULL,			0 },	// 6
    { CKA_VALUE,                NULL, 			0 },
    { CKA_SERIAL_NUMBER,        &serial_num,      sizeof(serial_num)},
  };
  CK_ATTRIBUTE template[] = {
    {CKA_ID, NULL, 0},
    {CKA_CLASS, NULL, 0},
  };

  CK_ATTRIBUTE      attr_update[] = {
    { CKA_LABEL, NULL, 0     },
  };
  CK_ULONG resultbuf_len;
  CK_OBJECT_HANDLE hObject;
  CK_ULONG foundObjs;

  struct tclpkcs11_interpdata *interpdata;
  struct tclpkcs11_handle *handle;
  char *tcl_handle = NULL;
  char *label;
  unsigned long certder_len;
  char *tcl_cert;
//  int tcl_cert_len;
  Py_ssize_t tcl_cert_len = 0;
  Py_ssize_t slotid_long = 0;
  CK_SLOT_ID slotid;
  CK_RV chk_rv;
  struct x509_object x509;
  ssize_t x509_read_ret;
  PyObject *hh;

  if (!cd) {
        PyErr_SetString(PyExc_TypeError, "pyp11_importcert: invalid hash_table");
	return NULL;
  }
  if (PyTuple_Size(args) != 4) {
        PyErr_SetString(PyExc_TypeError, "pyp11_importcert args error (count args != 3): importcert (handle, slot, cert_der_to_hex, pkcs11_label)");
	return NULL;
  }
  PyArg_ParseTuple(args, "sls#s", &tcl_handle, &slotid_long, &tcl_cert, &tcl_cert_len, &label);
//fprintf (stderr, "pyp11_importcert: handle=%s, slot=%u, tcl_cert=%s, tcl_cert_len=%i,label=%s\n", tcl_handle, slotid_long, tcl_cert, tcl_cert_len, label);

  interpdata = (struct tclpkcs11_interpdata *) cd;
  hh =  PyDict_GetItemString(interpdata->handles, tcl_handle);
  if (hh == NULL) {
        PyErr_SetString(PyExc_TypeError, "pyp11_importcert: invalid handle module)");
	return NULL;
  }
  tclpkcs11_string_to_bytearray(hh, (unsigned char *)&handle, sizeof(handle));

  if (!handle) {
        PyErr_SetString(PyExc_TypeError, "pyp11_importcert: 2 invalid handle module");
	return NULL;
  }

  slotid = slotid_long;

  chk_rv = tclpkcs11_start_session(handle, slotid);
  if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
  }
  cert_der = malloc(tcl_cert_len / 2);
  certder_len = tclpkcs11_string_to_bytearray(Py_BuildValue("s", tcl_cert), cert_der, tcl_cert_len / 2);

  //fprintf(stderr, "tclpkcs11_perform_pki_importcert certder_len=%lu\n", certder_len);
  x509_read_ret = asn1_x509_read_object(cert_der, certder_len, &x509);
  if (x509_read_ret == -1) {
        PyErr_SetString(PyExc_TypeError, "pyp11_importcert: bad certificate");
	return NULL;
  }

  //Заполняем templ
  templ_certimport[5].pValue = label;
  templ_certimport[5].ulValueLen = (unsigned long)strlen(label);
  templ_certimport[8].pValue = cert_der;
  templ_certimport[8].ulValueLen = certder_len;
  templ_certimport[6].pValue = x509.subject.asn1rep;
  templ_certimport[6].ulValueLen = x509.subject.asn1rep_len;
  templ_certimport[7].pValue = x509.issuer.asn1rep;
  templ_certimport[7].ulValueLen = x509.issuer.asn1rep_len;
  templ_certimport[9].pValue = x509.serial_number.asn1rep;
  templ_certimport[9].ulValueLen = x509.serial_number.asn1rep_len;
  attr_update[0].pValue = label;
  attr_update[0].ulValueLen = templ_certimport[5].ulValueLen;
  //fprintf(stderr, "tclpkcs11_perform_pki_importcert TEMPL END\n");
  //Заполняем templ конец
  //Calculare CKA_ID
  template[0].pValue = malloc(20);
  template[0].ulValueLen = 20;
  mechanism = &mechanism_desc_sha1;
  chk_rv = handle->pkcs11->C_DigestInit(handle->session, mechanism);
  if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
  }
  resultbuf_len = 20;
  chk_rv = handle->pkcs11->C_Digest(handle->session, (CK_BYTE *)(x509.pubkey.contents) + 1, x509.pubkey.size - 1, template[0].pValue, &resultbuf_len);
  if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
  }
  templ_certimport[2].pValue = template[0].pValue;
  templ_certimport[2].ulValueLen = template[0].ulValueLen;
  	
  //Calculare CKA_ID EMD
  /*Check exist certificate with the CKA_ID*/
  template[1].pValue = &oclass_cert;
  template[1].ulValueLen = sizeof(oclass_cert);
  chk_rv = handle->pkcs11->C_FindObjectsInit(handle->session, template, sizeof(template) / sizeof(CK_ATTRIBUTE));
  if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
  }

  chk_rv = handle->pkcs11->C_FindObjects(handle->session, &hObject, 1, &foundObjs);
  if (chk_rv != CKR_OK) {
	handle->pkcs11->C_FindObjectsFinal(handle->session);
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
  }
  /* Terminate Search */
  handle->pkcs11->C_FindObjectsFinal(handle->session);
  //fprintf(stderr, "tclpkcs11_perform_pki_importcert:cert final Find=%lu\n", foundObjs);

  if (foundObjs > 0) {
	char res[200];
	char *ckaid;
	tcl_result = tclpkcs11_bytearray_to_string(templ_certimport[2].pValue, templ_certimport[2].ulValueLen);
	PyArg_Parse(tcl_result, "s", &ckaid);
	sprintf(res, "pyp11_importcert: Certificate with the CKA_ID=%s exist", ckaid);
//        PyErr_SetString(PyExc_TypeError, "pyp11_importcert: Certificate with the CKA_ID=%s exist", ckaid);
        PyErr_SetString(PyExc_TypeError, res);
	return NULL;
  }

  chk_rv = handle->pkcs11->C_CreateObject(handle->session, templ_certimport, sizeof(templ_certimport) / sizeof(CK_ATTRIBUTE), &pub_key);
  if (chk_rv != CKR_OK) {
    if (chk_rv == 0x101) {
        PyErr_SetString(PyExc_TypeError, "importcert: cannot create object for certificate, not logged");
    } else {
        PyErr_SetString(PyExc_TypeError, "importcert:  cannot create object for certificate");
    }
    return NULL;
  }
  //    fprintf(stderr, "C_CreateObject certificate OK\n");
  /*Find publickey with the CKA_ID*/
  template[1].pValue = &oclass_pub;
  template[1].ulValueLen = sizeof(oclass_pub);

  chk_rv = handle->pkcs11->C_FindObjectsInit(handle->session, template, sizeof(template) / sizeof(template[0]));
  if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
  }

  chk_rv = handle->pkcs11->C_FindObjects(handle->session, &hObject, 1, &foundObjs);
  if (chk_rv != CKR_OK) {
    handle->pkcs11->C_FindObjectsFinal(handle->session);
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
  }
  /* Terminate Search */
  handle->pkcs11->C_FindObjectsFinal(handle->session);

  if (foundObjs == 1) {
    chk_rv = handle->pkcs11->C_SetAttributeValue(handle->session, hObject, attr_update,1);
    //fprintf(stderr, "Import set label to public_key\n");
  }
  /*Find privatekey with the CKA_ID*/
  template[1].pValue = &oclass_priv;
  template[1].ulValueLen = sizeof(oclass_priv);
  	
  chk_rv = handle->pkcs11->C_FindObjectsInit(handle->session, template, sizeof(template) / sizeof(template[0]));
  if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
  }

  chk_rv = handle->pkcs11->C_FindObjects(handle->session, &hObject, 1, &foundObjs);
  if (chk_rv != CKR_OK) {
    handle->pkcs11->C_FindObjectsFinal(handle->session);
//    Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
  }
  /* Terminate Search */
  handle->pkcs11->C_FindObjectsFinal(handle->session);

  if (foundObjs == 1) {
    chk_rv = handle->pkcs11->C_SetAttributeValue(handle->session, hObject, attr_update,1);
    //fprintf(stderr, "Import set label to private_key\n");
  }

  //finish:
  tcl_result = tclpkcs11_bytearray_to_string(templ_certimport[2].pValue, templ_certimport[2].ulValueLen);

  free(templ_certimport[2].pValue);
  //fprintf(stderr,"tclpkcs11_perform_pki_importcert OK\n");
  return (tcl_result);
}
static PyObject *
pyp11_parsecert(PyObject *self, PyObject *args) {
/*Usage pyp11.parsecert ([<handle>, <slot>,] <cert_der to hex>) => dict */
    extern struct tclpkcs11_interpdata *cd;
    int objc;
    char* signalgo;
  CK_BYTE *cert_der;
  CK_BYTE cka_id[20];
  PyObject *curr_item_list;
  int seek;
  unsigned char *pks;
  CK_MECHANISM     mechanism_desc_sha1 = { CKM_SHA_1, NULL, 0 };
  CK_MECHANISM_PTR mechanism;
  PyObject *obj_id, *obj_pubkeyinfo, *obj_pubkey, *obj_issuer, *obj_subject, *obj_serial_number, *obj_tbs_cert;
  PyObject  *obj_signature_algo;
  PyObject  *obj_signature;
  CK_ULONG resultbuf_len;

  struct tclpkcs11_interpdata *interpdata;
  struct tclpkcs11_handle *handle;
  char *tcl_handle;
  unsigned long certder_len;
  char *tcl_cert;
//  int tcl_cert_len;
  Py_ssize_t tcl_cert_len = 0;
  Py_ssize_t slotid_long = 0;
  CK_SLOT_ID slotid;
  CK_RV chk_rv;
  struct x509_object x509;
  ssize_t x509_read_ret;
  PyObject *hh;

  if (!cd) {
        PyErr_SetString(PyExc_TypeError, "pyp11.parsecert: invalid hash_table");
	return NULL;
  }
  objc = PyTuple_Size(args);
  if (objc == 3) {
	PyArg_ParseTuple(args, "sls#", &tcl_handle, &slotid_long, &tcl_cert, &tcl_cert_len);
//fprintf (stderr, "pyp11_parsecert: handle=%s, slot=%u, tcl_cert=%s, tcl_cert_len=%i\n", tcl_handle, slotid_long, tcl_cert, tcl_cert_len);
  } else if (objc == 1) {
	PyArg_ParseTuple(args, "s#", &tcl_cert, &tcl_cert_len);
//fprintf (stderr, "pyp11_parsecert: tcl_cert=%s, tcl_cert_len=%i\n", tcl_cert, tcl_cert_len);
  }  else {
        PyErr_SetString(PyExc_TypeError, "pyp11_parsecert args error (count args != 3): pyp11.parsecert ([handle, slot,] cert_der_to_hex");
	return NULL;
  }

  cert_der = malloc(tcl_cert_len / 2);
  //fprintf(stderr, "tclpkcs11_perform_pki_parsecert certder_len=%i\n", Tcl_GetCharLength(tcl_cert) / 2);
  certder_len = tclpkcs11_string_to_bytearray(Py_BuildValue("s", tcl_cert), cert_der, tcl_cert_len / 2);

  //fprintf(stderr, "tclpkcs11_perform_pki_parsecert certder_len=%lu\n", certder_len);
  x509_read_ret = asn1_x509_read_object(cert_der, certder_len, &x509);
  if (x509_read_ret == -1) {
        PyErr_SetString(PyExc_TypeError, "pyp11_parsecert: bad certificate");
	return NULL;
  }

//===============================
    /* Create the current item list */
  curr_item_list = PyDict_New();
  if (objc == 3) {
    interpdata = (struct tclpkcs11_interpdata *) cd;
    hh =  PyDict_GetItemString(interpdata->handles, tcl_handle);
    if (hh == NULL) {
        PyErr_SetString(PyExc_TypeError, "pyp11_parsecert: invalid handle module)");
	return NULL;
    }
    tclpkcs11_string_to_bytearray(hh, (unsigned char *)&handle, sizeof(handle));

    if (!handle) {
        PyErr_SetString(PyExc_TypeError, "pyp11_parsecert: 2 invalid handle module");
	return NULL;
    }
    slotid = slotid_long;
    chk_rv = tclpkcs11_start_session(handle, slotid);
    if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
    }
    //Calculate CKA_ID
    mechanism = &mechanism_desc_sha1;
    chk_rv = handle->pkcs11->C_DigestInit(handle->session, mechanism);
    if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
    }
    resultbuf_len = 20;
    chk_rv = handle->pkcs11->C_Digest(handle->session, (CK_BYTE *)(x509.pubkey.contents) + 1, x509.pubkey.size - 1, (CK_BYTE*)&cka_id, &resultbuf_len);
    if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
    }
    //Calculate CKA_ID EMD
    /* Convert the ID into a readable string */
    obj_id = tclpkcs11_bytearray_to_string((const unsigned char *)&cka_id, 20);
    PyDict_SetItem(curr_item_list, Py_BuildValue("s", "pkcs11_id"), obj_id);
  } else {
    PyDict_SetItem(curr_item_list, Py_BuildValue("s", "pkcs11_id"), Py_BuildValue("s", "-1"));
  }
  /* Convert the PUBKEYINFO into a readable string */
  pks = (unsigned char *)x509.pubkeyinfo.asn1rep;
  //fprintf(stderr,"tclpkcs11_perform_pki_pubketyinfo: List PKS=0x%2x,0x%2x,0x%2x,0x%2x,\n", pks[0], pks[1], pks[2], pks[3]);
  if ((unsigned char)pks[1] > (unsigned char)0x80) {
    seek = 3;
  } else {
    seek = 2;
  }
  /* Convert the subjectPublicKeyInfo into a readable string */
  obj_pubkeyinfo = tclpkcs11_bytearray_to_string((CK_BYTE *)(x509.pubkeyinfo.asn1rep) + seek, x509.pubkeyinfo.asn1rep_len - seek);
    PyDict_SetItem(curr_item_list, Py_BuildValue("s", "pubkeyinfo"), obj_pubkeyinfo);

  /* Convert the PUBKEY into a readable string */
  obj_pubkey = tclpkcs11_bytearray_to_string((CK_BYTE *)(x509.pubkey.contents) + 1, x509.pubkey.size - 1);
    PyDict_SetItem(curr_item_list, Py_BuildValue("s", "pubkey"), obj_pubkey);
  /* Convert the SUBJECT into a readable string */
  obj_subject = tclpkcs11_bytearray_to_string((CK_BYTE *)(x509.subject.asn1rep), x509.subject.asn1rep_len);
    PyDict_SetItem(curr_item_list, Py_BuildValue("s", "subject"), obj_subject);
  /* Convert the ISSUER into a readable string */
  obj_issuer = tclpkcs11_bytearray_to_string((CK_BYTE *)(x509.issuer.asn1rep), x509.issuer.asn1rep_len);
    PyDict_SetItem(curr_item_list, Py_BuildValue("s", "issuer"), obj_issuer);
  /* Convert the SERIAL_NUNBER into a readable string */
  obj_serial_number = tclpkcs11_bytearray_to_string((CK_BYTE *)(x509.serial_number.asn1rep), x509.serial_number.asn1rep_len);
    PyDict_SetItem(curr_item_list, Py_BuildValue("s", "serial_number"), obj_serial_number);
  /* Convert the tbsCertificate into a readable string */
  obj_tbs_cert = tclpkcs11_bytearray_to_string((CK_BYTE *)(x509.certificate.asn1rep), x509.certificate.asn1rep_len);
    PyDict_SetItem(curr_item_list, Py_BuildValue("s", "tbsCertificate"), obj_tbs_cert);
  /* Convert the signature_algo into a readable string */
  obj_signature_algo = tclpkcs11_bytearray_to_string((CK_BYTE *)(x509.signature_algo.asn1rep), x509.signature_algo.asn1rep_len);
    PyDict_SetItem(curr_item_list, Py_BuildValue("s", "signature_algo"), obj_signature_algo);
  /* Convert the signature into a readable string */
/*
  seek = (int)(x509.certificate.asn1rep - x509.wholething.asn1rep);
  obj_signature = tclpkcs11_bytearray_to_string((CK_BYTE *)(x509.signature.asn1rep), x509.signature.asn1rep_len );
*/

   PyArg_Parse(obj_signature_algo, "s", &signalgo);
    seek = 0;
    if (strstr(signalgo, "2a8503")) {
//Это ГОСТ-подпись
	if (x509.signature.asn1rep_len < 128) {
	    seek = x509.signature.asn1rep_len - 64;
	} else {
	    seek = x509.signature.asn1rep_len - 128;
	}
    }
  obj_signature = tclpkcs11_bytearray_to_string((CK_BYTE *)(x509.signature.asn1rep) + seek, x509.signature.asn1rep_len - seek);

//  obj_signature = tclpkcs11_bytearray_to_string((CK_BYTE *)(x509.signature_end.asn1rep), x509.signature_end.asn1rep_len);
    PyDict_SetItem(curr_item_list, Py_BuildValue("s", "signature"), obj_signature);

    return (curr_item_list);
}

static PyObject *
pyp11_closesession(PyObject *self, PyObject *args) {
/*Usage closesession (<handle>) => '1'|NULL */
    extern struct tclpkcs11_interpdata *cd;
  struct tclpkcs11_interpdata *interpdata;
  struct tclpkcs11_handle *handle;
  char *tcl_handle;
  int objc;
  PyObject *hh;

  if (!cd) {
        PyErr_SetString(PyExc_TypeError, "pyp11_closesession: invalid hash_table");
	return NULL;
  }
  objc = PyTuple_Size(args);
  if (objc != 1) {
        PyErr_SetString(PyExc_TypeError, "pyp11_closesession args error (count args != 1): closesession (handle)");
	return NULL;
//fprintf (stderr, "pyp11_closesession: handle=%s\n", tcl_handle);
  }
  PyArg_ParseTuple(args, "s", &tcl_handle);

  interpdata = (struct tclpkcs11_interpdata *) cd;
  hh =  PyDict_GetItemString(interpdata->handles, tcl_handle);
  if (hh == NULL) {
        PyErr_SetString(PyExc_TypeError, "pyp11_closesession: invalid handle module)");
	return NULL;
  }
  tclpkcs11_string_to_bytearray(hh, (unsigned char *)&handle, sizeof(handle));

  if (!handle) {
        PyErr_SetString(PyExc_TypeError, "pyp11_closesession: 2 invalid handle module");
	return NULL;
  }
  /* Close the session, cleaning up all the session objects */
  tclpkcs11_close_session(handle);
  return(Py_BuildValue("i", 1));
}
/*Это будет функция и для delete и для rename */

static PyObject *
pyp11_pki_delete(int del, PyObject *self, PyObject *args) {
/*Usage delete (<handle>, <slot>, type, <dict>) => dict */
//type = 'cert'| 'key'| 'obj'| 'all'
    extern struct tclpkcs11_interpdata *cd;
  /*del = 1 - delete, 0 -  rename*/
  struct tclpkcs11_interpdata *interpdata;
  struct tclpkcs11_handle *handle;
  char *mode;
  unsigned long tcl_strtobytearray_rv;
  PyObject *tcl_ckaid = NULL, *tcl_label, *tcl_obj = NULL;
  char *tcl_handle =  NULL;
  Py_ssize_t slotid_long = 0;
  static CK_OBJECT_CLASS     oclass_cert     = CKO_CERTIFICATE;
  static CK_OBJECT_CLASS oclass_pub  = CKO_PUBLIC_KEY;
  static CK_OBJECT_CLASS oclass_priv = CKO_PRIVATE_KEY;
  int i;
  CK_SLOT_ID slotid;
  CK_OBJECT_HANDLE hObject;
  CK_ULONG foundObjs;
  CK_ATTRIBUTE      attr_update[] = {
    { CKA_LABEL, NULL, 0     },
  };
  CK_ATTRIBUTE template[] = {
    {CKA_ID, NULL, 0},
    {CKA_CLASS, NULL, 0},
  };
  CK_RV chk_rv;
  PyObject *hh;

  PyObject *py_dict;
  PyObject *key, *value;
  Py_ssize_t pos = 0;
  char *kk, *val;
//  int len_val;
  Py_ssize_t len_val = 0;

  if (!cd) {
        PyErr_SetString(PyExc_TypeError, "pyp11_pki_delete: invalid hash_table");
	return NULL;
  }
  if (PyTuple_Size(args) != 4) {
        PyErr_SetString(PyExc_TypeError, "pyp11_delete args error (count args != 4): delete (handle, slot, type, dict)");
	return NULL;
  }
  PyArg_ParseTuple(args, "slsO", &tcl_handle, &slotid_long, &mode, &py_dict);
//    fprintf(stderr, "handle=%s, slot=%i\n", tcl_handle, slotid_long);
  interpdata = (struct tclpkcs11_interpdata *) cd;
  hh =  PyDict_GetItemString(interpdata->handles, tcl_handle);
  if (hh == NULL) {
        PyErr_SetString(PyExc_TypeError, "pyp11_delete: invalid handle module)");
	return NULL;
  }
  tclpkcs11_string_to_bytearray(hh, (unsigned char *)&handle, sizeof(handle));

  if (!handle) {
        PyErr_SetString(PyExc_TypeError, "pyp11_delete: 2 invalid handle module");
	return NULL;
  }
  i = 0;
  while (PyDict_Next(py_dict, &pos, &key, &value)) {
    PyArg_Parse(key, "s", &kk);
    PyArg_Parse(value, "s#", &val, &len_val);
    if (strcmp(kk, "hobj") == 0) {
      tcl_obj = value;
      i++;
      continue;
    }
    if (strcmp(kk, "pkcs11_id") == 0) {
      tcl_ckaid = value;
      //fprintf(stderr,"Delete CKA_ID=\"%s\" \nLenID=%i\n", Tcl_GetString(tcl_ckaid), Tcl_GetCharLength(tcl_ckaid) / 2);
      template[0].pValue = malloc(len_val / 2);
      tcl_strtobytearray_rv = tclpkcs11_string_to_bytearray(tcl_ckaid, template[0].pValue, len_val / 2);
      template[0].ulValueLen = tcl_strtobytearray_rv;
      //fprintf(stderr,"Delete LenID=%lu, temp=%lu\n", tcl_strtobytearray_rv, template[0].ulValueLen);
      i++;
      continue;
    }
    if (del == 0 ) {
      if (strcmp(kk, "pkcs11_label") == 0) {
        tcl_label = value;
        //fprintf(stderr,"CKA_LABEL=%s\n", Tcl_GetString(tcl_label));
        attr_update[0].type = CKA_LABEL;
        attr_update[0].pValue = val;
        attr_update[0].ulValueLen = (unsigned long)len_val;
        i++;
        continue;
      }
      if (strcmp(kk, "pkcs11_id_new") == 0) {
        tcl_label = value;
        //fprintf(stderr,"CKA_LABEL=%s\n", Tcl_GetString(tcl_label));
        attr_update[0].type = CKA_ID;
        attr_update[0].pValue = malloc(len_val / 2);
        attr_update[0].ulValueLen = tclpkcs11_string_to_bytearray(tcl_label, attr_update[0].pValue, len_val / 2);
        i++;
        continue;
      }
    }
//    fprintf(stderr, "i=%i, pos=%i, key=%s, val=%s, len_val=%i\n", i, pos, kk, val, len_val);
  }
  if (!tcl_obj && !tcl_ckaid) {
        PyErr_SetString(PyExc_TypeError, "pyp11_delete|rename: could not find element named \"pkcs11_id or hobj\" in dict");
	return NULL;
  }

  if ((del == 1) && (i != 1)) {
        PyErr_SetString(PyExc_TypeError, "pyp11_delete: could not find element named \"pkcs11_id \" in dict");
	return NULL;
  }
  if ((del == 0) && (i != 2)) {
        PyErr_SetString(PyExc_TypeError, "pyp11_rename: could not find element named \"pkcs11_label \" or \"pkcs11_id_new\" in dict");
	return NULL;
  }
    slotid = slotid_long;
    chk_rv = tclpkcs11_start_session(handle, slotid);
    if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
    }

  if (tcl_obj) {
    char *obj;
//    int len_obj;
    Py_ssize_t len_obj = 0;
    PyObject *obj_hobj;

    //Восстановление HANDLE объекта в функциях, где они будут задействованы
    PyArg_Parse(tcl_obj, "s#", &obj, &len_obj);
    obj_hobj = Py_BuildValue("s", obj + 4);
//    fprintf(stderr, "key=%s, val=%s, len_obj=%i\n", obj, obj + 4, (len_obj - 4) / 2);
//    tclpkcs11_string_to_bytearray(obj_hobj, (CK_OBJECT_HANDLE*)&hObject, (len_obj - 4) / 2);
    tclpkcs11_string_to_bytearray(obj_hobj, (unsigned char*)&hObject, (len_obj - 4) / 2);
    switch (del) {
      case 0:
        chk_rv = handle->pkcs11->C_SetAttributeValue(handle->session, hObject, attr_update,1);
        //fprintf(stderr, "Rename public_key\n");
        break;
      case 1:
        chk_rv = handle->pkcs11->C_DestroyObject(handle->session, hObject);
        //fprintf(stderr, "Delete public_key\n");
        break;
      default:
        break;
    }
    if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
    }
    return(Py_BuildValue("i", 1));
  }
  if (!strcmp((const char *)mode, "cert") || !strcmp((const char *)mode, "all")) {
//fprintf(stderr,"tclpkcs11_perform_pki_delete CERT mode=%s\n", mode);
    template[1].pValue = &oclass_cert;
    template[1].ulValueLen = sizeof(oclass_cert);
    chk_rv = handle->pkcs11->C_FindObjectsInit(handle->session, template, sizeof(template) / sizeof(template[0]));
    if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
    }

    chk_rv = handle->pkcs11->C_FindObjects(handle->session, &hObject, 1, &foundObjs);
    if (chk_rv != CKR_OK) {
      handle->pkcs11->C_FindObjectsFinal(handle->session);
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
    }
    /* Terminate Search */
    handle->pkcs11->C_FindObjectsFinal(handle->session);
//fprintf(stderr,"tclpkcs11_perform_pki_delete CERT mode=%s, foundObjs=%i\n", mode, foundObjs);

    if (foundObjs == 1) {
      switch (del) {
        case 0:
          chk_rv = handle->pkcs11->C_SetAttributeValue(handle->session, hObject, attr_update,1);
          //fprintf(stderr, "Rename cert\n");
          break;
        case 1:
          chk_rv = handle->pkcs11->C_DestroyObject(handle->session, hObject);
          //fprintf(stderr, "Delete cert");
          break;
        default:
          break;
      }
      if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
      }
    }
  }
  if (!strcmp((const char *)mode, "key") || !strcmp((const char *)mode, "all")) {
    //	CKO_PUBLIC_KEY
    template[1].pValue = &oclass_pub;
    template[1].ulValueLen = sizeof(oclass_pub);

    chk_rv = handle->pkcs11->C_FindObjectsInit(handle->session, template, sizeof(template) / sizeof(template[0]));
    if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
    }

    chk_rv = handle->pkcs11->C_FindObjects(handle->session, &hObject, 1, &foundObjs);
    if (chk_rv != CKR_OK) {
      handle->pkcs11->C_FindObjectsFinal(handle->session);
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
    }
    /* Terminate Search */
    handle->pkcs11->C_FindObjectsFinal(handle->session);

    if (foundObjs == 1) {
      switch (del) {
        case 0:
          chk_rv = handle->pkcs11->C_SetAttributeValue(handle->session, hObject, attr_update,1);
          //fprintf(stderr, "Rename public_key\n");
          break;
        case 1:
          chk_rv = handle->pkcs11->C_DestroyObject(handle->session, hObject);
          //fprintf(stderr, "Delete public_key\n");
          break;
        default:
          break;
      }
      if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
      }
    }

    //	CKO_PRIVATE_KEY
    //fprintf(stderr,"tclpkcs11_perform_pki_delete KEY mode=%s\n", mode);
    template[1].pValue = &oclass_priv;
    template[1].ulValueLen = sizeof(oclass_priv);

    chk_rv = handle->pkcs11->C_FindObjectsInit(handle->session, template, sizeof(template) / sizeof(template[0]));
    if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
    }

    chk_rv = handle->pkcs11->C_FindObjects(handle->session, &hObject, 1, &foundObjs);
    if (chk_rv != CKR_OK) {
        handle->pkcs11->C_FindObjectsFinal(handle->session);
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
    }
    /* Terminate Search */
    handle->pkcs11->C_FindObjectsFinal(handle->session);
//fprintf(stderr,"tclpkcs11_perform_pki_delete !!!! CERT mode=%s, foundObjs=%i\n", mode, foundObjs);

    if (foundObjs == 1) {
      switch (del) {
        case 0:
          //fprintf(stderr, "Rename private_key\n");
          chk_rv = handle->pkcs11->C_SetAttributeValue(handle->session, hObject, attr_update,1);
          break;
        case 1:
          chk_rv = handle->pkcs11->C_DestroyObject(handle->session, hObject);
          //fprintf(stderr, "Delete private_key\n");
          break;
        default:
          break;
      }
      if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
      }
    }

  }

  return(Py_BuildValue("i", 1));
}

static PyObject *
pyp11_delete(PyObject *self, PyObject *args) {
    int del;
    del = 1;
    return (pyp11_pki_delete(del, self, args));
}
static PyObject *
pyp11_rename(PyObject *self, PyObject *args) {
    int del;
    del = 0;
    return (pyp11_pki_delete(del, self, args));
}

static PyObject *
pyp11_pki_sign(PyObject *self, PyObject *args) {
/*Usage: pyp11.sign (<handle>, <slot>, <mech>, <digest doc>, <pkcs11_id | hobj_privkey>) => signature */
//mech = 'CKM_GOSTR3410_512'| 'CKM_GOSTR3410'
    extern struct tclpkcs11_interpdata *cd;
    int objc;
  struct tclpkcs11_interpdata *interpdata;
  struct tclpkcs11_handle *handle;
  unsigned char *input, resultbuf[1024];
  char *ckm_mech;
  char *p11idhobj;
//  int input_len;
  Py_ssize_t input_len = 0;
  CK_ULONG resultbuf_len;
  PyObject *tcl_objid = NULL, *tcl_objprivkey = NULL;
  char *tcl_handle = NULL;
  unsigned long tcl_strtobytearray_rv;
  PyObject *tcl_input;
  PyObject *tcl_result;
  Py_ssize_t slotid_long = 0;
  CK_SLOT_ID slotid;
  CK_MECHANISM     mechanism_desc = { CKM_GOSTR3410, NULL, 0 };
  CK_MECHANISM     mechanism_desc_512 = { CKM_GOSTR3410_512, NULL, 0 };
  CK_MECHANISM_PTR mechanism;
  CK_RV chk_rv;
  PyObject *hh;
  CK_OBJECT_HANDLE hObject;
  CK_ULONG foundObjs;
  CK_OBJECT_CLASS objectclass_pk;

  CK_ATTRIBUTE template[] = {
    {CKA_ID, NULL, 0},
    {CKA_CLASS, NULL, 0},
  };

  if (!cd) {
        PyErr_SetString(PyExc_TypeError, "pyp11_pki_sign: invalid hash_table");
	return NULL;
  }
  objc = PyTuple_Size(args);
  if (objc != 5) {
        PyErr_SetString(PyExc_TypeError, "pyp11_sign args error (count args != 5): pyp11.sign (<handle>, <slot>, <mech>, <digest doc>, <pkcs11_id | hobj_privkey>)");
	return NULL;
  }
  PyArg_ParseTuple(args, "slsOO", &tcl_handle, &slotid_long, &ckm_mech, &tcl_input, &tcl_objid);

  /* HASH for SIGN */
  PyArg_Parse(tcl_input, "s#", &input, &input_len);
  input = malloc(input_len / 2);
  input_len = tclpkcs11_string_to_bytearray(tcl_input, input, input_len / 2);

  //fprintf(stderr, "tclpkcs11_perform_pki_sign input_len=%i, nickcert=%s\n", input_len, ckm_mech);
  if (!memcmp("CKM_GOSTR3410_512", ckm_mech, 17)) {
    mechanism = &mechanism_desc_512;
    resultbuf_len = 128;
    if (input_len != 64) {
        PyErr_SetString(PyExc_TypeError, "\"pyp11.sign CKM_GOSTR3410_512 input\" - bad len hash");
	return NULL;
    }
  } else if (!memcmp("CKM_GOSTR3410", ckm_mech, 13)) {
    mechanism = &mechanism_desc;
    resultbuf_len = 64;
    if (input_len != 32) {
        PyErr_SetString(PyExc_TypeError, "\"pyp11.sign CKM_GOSTR3410 input\" - bad len hash");
	return NULL;
    }
  } else {
        PyErr_SetString(PyExc_TypeError, "\"pyp11.sign CKM_GOSTR3410|CKM_GOSTR3410_512 input\" - bad CKM sign");
	return NULL;
  }
  PyArg_Parse(tcl_objid, "s", &p11idhobj);
  if ( !strncmp (p11idhobj, "hobj", 4) || !strncmp (p11idhobj, "HOBJ", 4)) {
      tcl_objprivkey = tcl_objid;
      tcl_objid = NULL;
  }

  if (!tcl_objid && !tcl_objprivkey) {
        PyErr_SetString(PyExc_TypeError, "\"pyp11.sign \" - could not find element named \"pkcs11_id or hobj_privkey\"");
	return NULL;
  }

  interpdata = (struct tclpkcs11_interpdata *) cd;
  hh =  PyDict_GetItemString(interpdata->handles, tcl_handle);
  if (hh == NULL) {
        PyErr_SetString(PyExc_TypeError, "pyp11.sign: invalid handle module)");
	return NULL;
  }
  tclpkcs11_string_to_bytearray(hh, (unsigned char *)&handle, sizeof(handle));

  if (!handle) {
        PyErr_SetString(PyExc_TypeError, "pyp11.sign: 2 invalid handle module");
	return NULL;
  }
    slotid = slotid_long;
    chk_rv = tclpkcs11_start_session(handle, slotid);
    if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
    }

  if (!tcl_objprivkey) {
    char *obj;
//    int lenobj;
    Py_ssize_t lenobj = 0;
    PyArg_Parse(tcl_objid, "s#", &obj, &lenobj);
// fprintf(stderr, "pki_sign  obj1=%s len=%u\n", obj, lenobj);
    /* CKA_ID */
    template[0].pValue = malloc(lenobj / 2);
    tcl_strtobytearray_rv = tclpkcs11_string_to_bytearray(tcl_objid, template[0].pValue, lenobj / 2);
    template[0].ulValueLen = tcl_strtobytearray_rv;

    /* CKA_CLASS */
    objectclass_pk = CKO_PRIVATE_KEY;
    template[1].pValue = &objectclass_pk;
    template[1].ulValueLen = sizeof(objectclass_pk);

    chk_rv = handle->pkcs11->C_FindObjectsInit(handle->session, template, sizeof(template) / sizeof(template[0]));
    if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
    }

    chk_rv = handle->pkcs11->C_FindObjects(handle->session, &hObject, 1, &foundObjs);
    if (chk_rv != CKR_OK) {
        handle->pkcs11->C_FindObjectsFinal(handle->session);
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
    }

    /* Terminate Search */
    handle->pkcs11->C_FindObjectsFinal(handle->session);

    if (foundObjs < 1) {
        PyErr_SetString(PyExc_TypeError, "pyp11_sign: PKCS11_ERROR MAYBE_LOGIN");
	return NULL;
    }
  } else {
    char *obj;
//    int lenobj;
    Py_ssize_t lenobj = 0;
    PyObject *obj_hobj;

    //Восстановление HANDLE объекта в функциях, где они будут задействованы
    PyArg_Parse(tcl_objprivkey, "s#", &obj, &lenobj);
    obj_hobj = Py_BuildValue("s", obj + 4);
// fprintf(stderr, "pki_sign  obj1=%s, obj2=%s\n", obj, obj + 4);
//    tclpkcs11_string_to_bytearray(obj_hobj, (CK_OBJECT_HANDLE*)&hObject, (lenobj - 4) / 2);
    tclpkcs11_string_to_bytearray(obj_hobj, (unsigned char*)&hObject, (lenobj - 4) / 2);
  }
  //fprintf(stderr, "tclpkcs11_perform_pki_sign=PRIV_KEY FIND\n");
  chk_rv = handle->pkcs11->C_SignInit(handle->session, mechanism, hObject);
  if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
  }

  //fprintf(stderr, "tclpkcs11_perform_pki_sign Init OK\n");
  chk_rv = handle->pkcs11->C_Sign(handle->session, input, input_len, resultbuf, &resultbuf_len);
  if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
  }

  tcl_result = tclpkcs11_bytearray_to_string(resultbuf, resultbuf_len);
  return(tcl_result);
}


#define PK11_SETATTRS(x,id,v,l) (x)->type = (id); \
(x)->pValue=(v); (x)->ulValueLen = (l);

static PyObject *
pyp11_pki_importkey(PyObject *self, PyObject *args) {
    extern struct tclpkcs11_interpdata *cd;
    int objc;
  static CK_BBOOL        ltrue       = CK_TRUE;
  static CK_BBOOL        lfalse      = CK_FALSE;
  /*
  static CK_BYTE         gost28147params[] = {
  0x06, 0x09, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x05, 0x01, 0x01
  };
  */
  CK_VOID_PTR       pval[20];
  int cv;
  CK_KEY_TYPE key_type = CKK_GOSTR3410;
  CK_KEY_TYPE key_type_512 = CKK_GOSTR3410_512;

  CK_ATTRIBUTE pub_tmpl[20];
  CK_ATTRIBUTE priv_tmpl[20];
  CK_ATTRIBUTE *attrs_pub = NULL;
  CK_ATTRIBUTE *attrs_priv = NULL;
  CK_ULONG pub_tmplCount;
  CK_ULONG priv_tmplCount;

  unsigned long tcl_strtobytearray_rv;
  static CK_OBJECT_CLASS oclass_pubk  = CKO_PUBLIC_KEY;
  static CK_OBJECT_CLASS oclass_privk = CKO_PRIVATE_KEY;

  CK_ATTRIBUTE template[] = {
    {CKA_ID, NULL, 0},
    {CKA_CLASS, NULL, 0},
  };
  CK_OBJECT_HANDLE hObj = CK_INVALID_HANDLE;
  CK_OBJECT_HANDLE hObjPr = CK_INVALID_HANDLE;
  CK_OBJECT_HANDLE hObject;
  CK_ULONG foundObjs;

  struct tclpkcs11_interpdata *interpdata;
  struct tclpkcs11_handle *handle;
  int i;
  char *tcl_handle = NULL;
  //	unsigned long certder_len;
  PyObject *tcl_keylist, **tcl_keylist_values, *tcl_keylist_key, *tcl_keylist_val;
  PyObject *tcl_label = NULL;
  PyObject *tcl_ckaid = NULL;
  PyObject *tcl_priv_value = NULL;
  PyObject *tcl_priv_export = NULL;
  PyObject *tcl_gosthash = NULL;
  PyObject *tcl_gostsign = NULL;
  PyObject *tcl_pub_value = NULL;
  PyObject *hh;
  PyObject *py_dict = NULL;
  PyObject *key, *value;
  Py_ssize_t pos = 0;
  char *kk, *val;
//  int len_val;
  Py_ssize_t len_val = 0;
  Py_ssize_t slotid_long = 0;
  int tcl_keylist_llength, idx;
  CK_SLOT_ID slotid;
  CK_RV chk_rv;
  int tcl_rv;

  if (!cd) {
        PyErr_SetString(PyExc_TypeError, "pyp11.importkey: invalid hash_table");
	return NULL;
  }
  //fprintf(stderr, "tclpkcs11_perform_pki_importkey objc=%d\n",  objc);
  objc = PyTuple_Size(args);
  if (objc != 3) {
        PyErr_SetString(PyExc_TypeError, "wrong # args: should be \"pyp11.importkey (<handle>, <slot>,  <dict (list_token and cka for keys>)\"");
	return NULL;
  }
  PyArg_ParseTuple(args, "slO", &tcl_handle, &slotid_long, &py_dict);
  slotid = slotid_long;
  interpdata = (struct tclpkcs11_interpdata *) cd;
  hh =  PyDict_GetItemString(interpdata->handles, tcl_handle);
  if (hh == NULL) {
        PyErr_SetString(PyExc_TypeError, "pyp11.importkey: invalid handle module)");
	return NULL;
  }
  tclpkcs11_string_to_bytearray(hh, (unsigned char *)&handle, sizeof(handle));

  if (!handle) {
        PyErr_SetString(PyExc_TypeError, "pyp11.importkey: 2 invalid handle module");
	return NULL;
  }
//Разбираем словарь
  i = 0;
  while (PyDict_Next(py_dict, &pos, &key, &value)) {
    PyArg_Parse(key, "s", &kk);
//    PyArg_Parse(value, "s#", &val, &len_val);
//fprintf(stderr, "pyp11_pki_importkey 1 i=%i: len=%i\n", i,  len_val);
    if (strcmp(kk, "pkcs11_label") == 0) {
      tcl_label = value;
    } else if (strcmp(kk, "pkcs11_id") == 0) {
      tcl_ckaid = value;
    } else if (strcmp(kk, "priv_value") == 0) {
      tcl_priv_value = value;
    } else if (strcmp(kk, "pub_value") == 0) {
      tcl_pub_value = value;
    } else if (strcmp(kk, "priv_export") == 0) {
      tcl_priv_export = value;
    } else if (strcmp(kk, "gosthash") == 0) {
      tcl_gosthash = value;
    } else if (strcmp(kk, "gostsign") == 0) {
      tcl_gostsign = value;
    } else {
	PyErr_SetString(PyExc_TypeError, "bad key to dict: should be \"pyp11.importkey (<handle>, <slot>,  <dict (list_token and cka for keys>)\"");
	return NULL;
    }
    i++;
  }
  if (i != 7) {
        PyErr_SetString(PyExc_TypeError, "wrong # args to dict: should be \"pyp11.importkey (<handle>, <slot>,  <dict (list_token and cka for keys>)\"");
	return NULL;
  }
  //fprintf(stderr,"tclpkcs11_perform_pki_importkey: List END i=%i\n", i);

  chk_rv = tclpkcs11_start_session(handle, slotid);
  if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
  }
  cv = 0;
  PyArg_Parse(tcl_ckaid, "s#", &val, &len_val);
  pval[cv] = malloc(len_val / 2);
  template[0].pValue = pval[cv];
  cv++;
  pval[cv] = NULL;
  	
  tcl_strtobytearray_rv = tclpkcs11_string_to_bytearray(tcl_ckaid, template[0].pValue, len_val / 2);
  template[0].ulValueLen = tcl_strtobytearray_rv;
  template[1].pValue = &oclass_privk;
  template[1].ulValueLen = sizeof(oclass_privk);

  chk_rv = handle->pkcs11->C_FindObjectsInit(handle->session, template, sizeof(template) / sizeof(CK_ATTRIBUTE));
  if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
  }

  chk_rv = handle->pkcs11->C_FindObjects(handle->session, &hObject, 1, &foundObjs);
  if (chk_rv != CKR_OK) {
	free(template[0].pValue);
	handle->pkcs11->C_FindObjectsFinal(handle->session);
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
  }
  /* Terminate Search */
  handle->pkcs11->C_FindObjectsFinal(handle->session);
  //fprintf(stderr, "tclpkcs11_perform_pki_importkey:private key final Find=%lu\n", foundObjs);

  if (foundObjs > 0) {
    free(template[0].pValue);
    PyErr_SetString(PyExc_TypeError, "pyp11.importkey: Private Key with the CKA_ID exist");
    return NULL;
  }

  template[1].pValue = &oclass_pubk;
  template[1].ulValueLen = sizeof(oclass_pubk);

  chk_rv = handle->pkcs11->C_FindObjectsInit(handle->session, template, sizeof(template) / sizeof(CK_ATTRIBUTE));
  if (chk_rv != CKR_OK) {
	free(template[0].pValue);
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
  }

  chk_rv = handle->pkcs11->C_FindObjects(handle->session, &hObject, 1, &foundObjs);
  if (chk_rv != CKR_OK) {
    free(template[0].pValue);
    handle->pkcs11->C_FindObjectsFinal(handle->session);
    PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
    return NULL;
  }
  /* Terminate Search */
  handle->pkcs11->C_FindObjectsFinal(handle->session);
  //fprintf(stderr, "tclpkcs11_perform_pki_importkey:public key final Find=%lu\n", foundObjs);

  if (foundObjs > 0) {
    free(template[0].pValue);
    PyErr_SetString(PyExc_TypeError, "pyp11.importkey: Public Key with the CKA_ID exist");
    return NULL;
  }

  attrs_pub = pub_tmpl;
  attrs_priv = priv_tmpl;
  PK11_SETATTRS(attrs_priv, CKA_TOKEN, &ltrue, sizeof(ltrue)); attrs_priv++;
  PK11_SETATTRS(attrs_pub, CKA_TOKEN, &ltrue, sizeof(ltrue)); attrs_pub++;
  PK11_SETATTRS(attrs_pub, CKA_PRIVATE, &lfalse, sizeof(lfalse)); attrs_pub++;
  PK11_SETATTRS(attrs_priv, CKA_PRIVATE, &ltrue, sizeof(ltrue)); attrs_priv++;

  PK11_SETATTRS(attrs_pub, CKA_CLASS, &oclass_pubk, sizeof(oclass_pubk)); attrs_pub++;
  PK11_SETATTRS(attrs_priv, CKA_CLASS, &oclass_privk, sizeof(oclass_privk)); attrs_priv++;
  PyArg_Parse(tcl_priv_value, "s#", &val, &len_val);
  if (len_val == 64) {
    PK11_SETATTRS(attrs_pub, CKA_KEY_TYPE, &key_type, sizeof(key_type)); attrs_pub++;
    PK11_SETATTRS(attrs_priv, CKA_KEY_TYPE, &key_type, sizeof(key_type)); attrs_priv++;
  } else if (len_val == 128) {
    PK11_SETATTRS(attrs_pub, CKA_KEY_TYPE, &key_type_512, sizeof(key_type_512)); attrs_pub++;
    PK11_SETATTRS(attrs_priv, CKA_KEY_TYPE, &key_type_512, sizeof(key_type_512)); attrs_priv++;
  } else {
    char res[200];
    free(template[0].pValue);
//    sprintf(res, "pyp11_importcert: pyp11.importkey: bad length private key=%i exist\nvalue=%s", len_val, val);
    sprintf(res, "pyp11_importcert: pyp11.importkey: bad length private key=%i", (int)len_val);
    PyErr_SetString(PyExc_TypeError, res);
    return NULL;
  }
  PK11_SETATTRS(attrs_priv, CKA_ID, pval[0], 20); attrs_priv++;
  PK11_SETATTRS(attrs_pub, CKA_ID, pval[0], 20); attrs_pub++;
  PyArg_Parse(tcl_label, "s#", &val, &len_val);
  PK11_SETATTRS(attrs_priv, CKA_LABEL, val, len_val + 1); attrs_priv++;
  PK11_SETATTRS(attrs_pub, CKA_LABEL, val, len_val + 1); attrs_pub++;
  PK11_SETATTRS(attrs_pub, CKA_ENCRYPT, &ltrue, sizeof(ltrue)); attrs_pub++;
  PK11_SETATTRS(attrs_pub, CKA_VERIFY, &ltrue, sizeof(ltrue)); attrs_pub++;
  PK11_SETATTRS(attrs_pub, CKA_WRAP, &ltrue, sizeof(ltrue)); attrs_pub++;
  PyArg_Parse(tcl_priv_export, "s", &val);
  if(strcmp(val, "true") != 0 ) {
    PK11_SETATTRS(attrs_priv, CKA_EXTRACTABLE, &lfalse, sizeof(lfalse)); attrs_priv++;
    //	    PK11_SETATTRS(attrs_priv, CKA_SENSITIVE, &ltrue, sizeof(ltrue)); attrs_priv++;
  }
  else{
    PK11_SETATTRS(attrs_priv, CKA_EXTRACTABLE, &ltrue, sizeof(ltrue)); attrs_priv++;
    PK11_SETATTRS(attrs_priv, CKA_SENSITIVE, &lfalse, sizeof(lfalse)); attrs_priv++;
  }
  PK11_SETATTRS(attrs_priv, CKA_DECRYPT, &ltrue, sizeof(ltrue)); attrs_priv++;
  PK11_SETATTRS(attrs_priv, CKA_UNWRAP, &ltrue, sizeof(ltrue)); attrs_priv++;
  PK11_SETATTRS(attrs_priv, CKA_SIGN, &ltrue, sizeof(ltrue)); attrs_priv++;
  PK11_SETATTRS(attrs_priv, CKA_DERIVE, &ltrue, sizeof(ltrue)); attrs_priv++;

  PyArg_Parse(tcl_gosthash, "s#", &val, &len_val);
  pval[cv] = malloc(len_val / 2);
  tcl_strtobytearray_rv = tclpkcs11_string_to_bytearray(tcl_gosthash, pval[cv], len_val / 2);
  PK11_SETATTRS(attrs_priv, CKA_GOSTR3411PARAMS, pval[cv], len_val / 2); attrs_priv++;
  PK11_SETATTRS(attrs_pub, CKA_GOSTR3411PARAMS, pval[cv], len_val / 2); attrs_pub++;
  cv ++;
  PyArg_Parse(tcl_gostsign, "s#", &val, &len_val);
  pval[cv] = malloc(len_val / 2);
  tcl_strtobytearray_rv = tclpkcs11_string_to_bytearray(tcl_gostsign, pval[cv], len_val / 2);
  PK11_SETATTRS(attrs_priv, CKA_GOSTR3410PARAMS, pval[cv], len_val / 2); attrs_priv++;
  PK11_SETATTRS(attrs_pub, CKA_GOSTR3410PARAMS, pval[cv], len_val / 2); attrs_pub++;
  cv ++;

  PyArg_Parse(tcl_priv_value, "s#", &val, &len_val);
fprintf(stderr, "pyp11_pki_importkey: privk=%s, len=%i\n",  val, (int)len_val);
  pval[cv] = malloc(len_val / 2);
  tcl_strtobytearray_rv = tclpkcs11_string_to_bytearray(tcl_priv_value, pval[cv], len_val / 2);
  PK11_SETATTRS(attrs_priv, CKA_VALUE, pval[cv], len_val / 2); attrs_priv++;
  cv ++;
  PyArg_Parse(tcl_pub_value, "s#", &val, &len_val);
  pval[cv] = malloc(len_val / 2);
  tcl_strtobytearray_rv = tclpkcs11_string_to_bytearray(tcl_pub_value, pval[cv], len_val / 2);
  PK11_SETATTRS(attrs_pub, CKA_VALUE, pval[cv], len_val / 2); attrs_pub++;
  cv ++;
  pval[cv] = NULL;

  pub_tmplCount = (attrs_pub - pub_tmpl);
  chk_rv = handle->pkcs11->C_CreateObject(handle->session, pub_tmpl, pub_tmplCount, &hObj);
  if (chk_rv != CKR_OK) {
    cv = 0;
    while (pval[cv] != NULL) {
      free(pval[cv]);
      pval[cv] = NULL;
      cv++;
    }
    PyErr_SetString(PyExc_TypeError, "pyp11.importkey: cannot create publickey");
    return NULL;
  }
  priv_tmplCount = (attrs_priv - priv_tmpl);
  chk_rv = handle->pkcs11->C_CreateObject(handle->session, priv_tmpl, priv_tmplCount, &hObjPr);
  if (chk_rv != CKR_OK) {
    cv = 0;
    while (pval[cv] != NULL) {
      free(pval[cv]);
      pval[cv] = NULL;
      cv++;
    }
    PyErr_SetString(PyExc_TypeError, "pyp11.importkey: cannot create publickey");
    return NULL;
  }

  cv = 0;
  while (pval[cv] != NULL) {
    free(pval[cv]);
    pval[cv] = NULL;
    cv++;
  }
  return(Py_BuildValue("i", 1));
}

static PyObject *
pyp11_pki_verify(PyObject *self, PyObject *args) {
/*Usage: pyp11.verify (<handle>, <slot>, <digest_hex>, <signature_hex>, <pubkeyinfo_hex>) => 1|NULL */
//mech = 'CKM_GOSTR3410_512'| 'CKM_GOSTR3410'
    extern struct tclpkcs11_interpdata *cd;
    int objc;
  static CK_BBOOL        ltrue       = CK_TRUE;
  static CK_BBOOL        lfalse       = CK_FALSE;
  static CK_OBJECT_CLASS oclass_pub  = CKO_PUBLIC_KEY;
  CK_KEY_TYPE     key_type    = CKK_GOSTR3410; //CKK_GOSTR3410_512
  static CK_UTF8CHAR     *label         = (CK_UTF8CHAR *)"Yet Another Keypair";
  static CK_BYTE         gost28147params[] = {
    0x06, 0x09, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x05, 0x01, 0x01
  };
  CK_BYTE *digest;
  CK_BYTE *signature;
  CK_BYTE *pubkeyinfo;
  CK_OBJECT_HANDLE pub_key = CK_INVALID_HANDLE;
  CK_MECHANISM           mechanism_desc     = { CKM_GOSTR3410, NULL, 0 };
  CK_MECHANISM           mechanism_desc_512     = { CKM_GOSTR3410_512, NULL, 0 };
  CK_MECHANISM_PTR       mechanism          = &mechanism_desc;

  CK_ULONG label_len = (unsigned long)strlen((char *)label) + 1;
  CK_ATTRIBUTE           pub_template[] = {
    { CKA_CLASS,		&oclass_pub,		sizeof(oclass_pub)},
    { CKA_KEY_TYPE,		&key_type,		sizeof(key_type)},
    { CKA_TOKEN,		&lfalse,		sizeof(lfalse)},
    { CKA_GOSTR3410PARAMS,	NULL, 			0},
    { CKA_GOSTR3411PARAMS,	NULL, 			0},
    { CKA_GOST28147_PARAMS, 	gost28147params,	sizeof(gost28147params)	},
    { CKA_VERIFY,		&ltrue,			sizeof(CK_BBOOL)},
    { CKA_ENCRYPT,		&ltrue,			sizeof(CK_BBOOL)},
    { CKA_LABEL,		NULL,			0 },
    { CKA_VALUE,		NULL,			0 },
  };
  struct tclpkcs11_interpdata *interpdata;
  struct tclpkcs11_handle *handle;
  char  *tcl_handle;
  PyObject *tcl_pubkeyinfo = NULL;
  unsigned long digest_len;
  unsigned long signature_len;
  PyObject *tcl_hash, *tcl_signature;
  Py_ssize_t slotid_long = 0;
  CK_SLOT_ID slotid;
  CK_RV chk_rv;
  PyObject *hh;
  //fprintf(stderr, "tclpkcs11_perform_pki_verify objc=%d\n",  objc);
    char *obj;
//    int lenobj;
    Py_ssize_t lenobj = 0;

  if (!cd) {
        PyErr_SetString(PyExc_TypeError, "pki_verify: invalid hash_table");
	return NULL;
  }
  objc = PyTuple_Size(args);
  if (objc != 5) {
        PyErr_SetString(PyExc_TypeError, "pki_verify args error (count args != 5): pyp11.verify (<handle>, <slot>, <digest_hex>, <signature_hex>, <pubkeyinfo_hex>)");
	return NULL;
  }
  PyArg_ParseTuple(args, "slOOO", &tcl_handle, &slotid_long, &tcl_hash, &tcl_signature, &tcl_pubkeyinfo);


//  tcl_hash: hash from doc*/
  //fprintf(stderr,"HASH=%s\n", Tcl_GetString(tcl_hash));
    PyArg_Parse(tcl_hash, "s#", &obj, &lenobj);
  digest = malloc(lenobj / 2);
  //fprintf(stderr, "tclpkcs11_perform_pki_verify digest_len=%i\n", Tcl_GetCharLength(tcl_hash) / 2);
  digest_len = tclpkcs11_string_to_bytearray(tcl_hash, digest, lenobj / 2);
  //fprintf(stderr, "tclpkcs11_perform_pki_verify digest_len=%lu\n", digest_len);
  if (digest_len != 32 && digest_len != 64) {
        PyErr_SetString(PyExc_TypeError, "pki_verify: bad length (32|64) hash ");
	return NULL;
  }
//  tcl_signature: signature doc
    PyArg_Parse(tcl_signature, "s#", &obj, &lenobj);
  signature = malloc(lenobj / 2);
  signature_len = tclpkcs11_string_to_bytearray(tcl_signature, signature, lenobj / 2);
  if (signature_len != 64 && signature_len != 128) {
        PyErr_SetString(PyExc_TypeError, "pki_verify: bad length (64|128) signatute ");
	return NULL;
  }
  //fprintf(stderr, "tclpkcs11_perform_pki_verify signature_len=%lu\n", signature_len);
    if (tcl_pubkeyinfo != NULL) {
      CK_BYTE oidgost[] = {0x2a, 0x85, 0x03};
      CK_BYTE hexoidpk512[] = {0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x1, 0x02};
      int l, l1, seek;
      CK_BYTE *pki, *pkv;
      //fprintf(stderr,"PUBKEYINFO=%s\nPUBKEYINFO_LEN_alloc=%i\n", Tcl_GetString(tcl_pubkeyinfo), Tcl_GetCharLength(tcl_pubkeyinfo) / 2);
      PyArg_Parse(tcl_pubkeyinfo, "s#", &obj, &lenobj);
      pubkeyinfo = malloc(lenobj / 2);
      tclpkcs11_string_to_bytearray(tcl_pubkeyinfo, pubkeyinfo, lenobj / 2);
      //fprintf(stderr,"PUBKEYINFO_LEN=%lu\n", tcl_strtobytearray_rv);
      pki = pubkeyinfo;
      if (pki[0] != 0x30){
        PyErr_SetString(PyExc_TypeError, "pki_verify: invalid pubkeyinfo");
	return NULL;
      }
      l = (int)pki[1];
      pki += 2;
      if (pki[l] != 0x03) {
        PyErr_SetString(PyExc_TypeError, "pki_verify: invalid pubkeyinfo 1");
	return NULL;
      }
      //fprintf(stderr,"PUBKEYINFO 1111 LENPAR l=%i, p0=0x%x,p1=0x%x,p2=0x%x\n", l, pki[l + 0], pki[l + 1], pki[l + 2]);
      if (pki[l + 1] > 0x80) {
        seek = 6;
        l1 = 128;
      } else {
        seek = 4;
        l1 = 64;
      }
      //Начало ключа
      pkv = pki + 1 + seek + l;
      pub_template[9].pValue = malloc(l1);
      //fprintf(stderr,"PUBKEYINFO 1111PVK LENPAR l1=%i, p0=0x%x,p1=0x%x,p2=0x%x\n", l1, pkv[0], pkv[1], pkv[2]);
      memmove (pub_template[9].pValue, pkv, l1);
      pub_template[9].ulValueLen = l1;
      //Параметры
      if (pki[0] != 0x06) {
        PyErr_SetString(PyExc_TypeError, "pki_verify: invalid pubkeyinfo 2");
	return NULL;
      }
      //Тип ключа
      l = (int)pki[1];
      pki += 2;
      //fprintf(stderr,"PUBKEYINFO LENPAR TPK l=%i, p0=0x%x,p1=0x%x,p2=0x%x\n", l, pki[0], pki[1], pki[2]);
      if (memcmp(pki, oidgost, sizeof(oidgost))) {
        PyErr_SetString(PyExc_TypeError, "pki_verify: invalid pubkeyinfo bad type key (not gost)");
	return NULL;
      }
      if (!memcmp(pki, hexoidpk512, sizeof(hexoidpk512))) {
        key_type = CKK_GOSTR3410_512;
        mechanism = &mechanism_desc_512;
        if (digest_len != 64) {
    	    PyErr_SetString(PyExc_TypeError, "pki_verify  CKK_GOSTR3410_512 digest:  - bad len hash");
	    return NULL;
        }
      } else {
        key_type = CKK_GOSTR3410;
        mechanism = &mechanism_desc;
        if (digest_len != 32) {
    	    PyErr_SetString(PyExc_TypeError, "pki_verify  CKK_GOSTR3410 digest:  - bad len hash");
	    return NULL;
        }
      }

      pki = pki + l + 2;
      //gostr3410param
      //fprintf(stderr,"PUBKEYINFO SIGN LENPAR l=%i, p0=0x%x,p1=0x%x,p2=0x%x\n", l, pki[0], pki[1], pki[2]);
      l = (int)pki[1];
      pub_template[3].pValue = malloc(l + 2);
      memcpy(pub_template[3].pValue, pki, l + 2);
      pub_template[3].ulValueLen = l + 2;
      //gostr3411param

      pki = pki + l + 2;
      l = (int)pki[1];
      //fprintf(stderr,"PUBKEYINFO HASH LENPAR l=%i, p0=0x%x,p1=0x%x,p2=0x%x\n", l, pki[0], pki[1], pki[2]);
      pub_template[4].pValue = malloc(l + 2);
      memcpy(pub_template[4].pValue, pki, l + 2);
      pub_template[4].ulValueLen = l + 2;
    }

  pub_template[8].pValue = label;
  pub_template[8].ulValueLen = label_len;

  interpdata = (struct tclpkcs11_interpdata *) cd;
  hh =  PyDict_GetItemString(interpdata->handles, tcl_handle);
  if (hh == NULL) {
        PyErr_SetString(PyExc_TypeError, "pyp11.pki_verify: invalid handle module)");
	return NULL;
  }
  tclpkcs11_string_to_bytearray(hh, (unsigned char *)&handle, sizeof(handle));

  if (!handle) {
        PyErr_SetString(PyExc_TypeError, "pyp11.pki_verify: 2 invalid handle module");
	return NULL;
  }
    slotid = slotid_long;
    chk_rv = tclpkcs11_start_session(handle, slotid);
    if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
    }

  //fprintf(stderr,"tclpkcs11_perform_pki_verify SESSION OK\n");
  chk_rv = handle->pkcs11->C_CreateObject(handle->session, pub_template, sizeof(pub_template) / sizeof(CK_ATTRIBUTE), &pub_key);
  if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, "pyp11.verify: cannot create publickey");
	return NULL;
  }
  //fprintf(stderr, "C_CreateObject public key OK\n");
  chk_rv = handle->pkcs11->C_VerifyInit(handle->session, mechanism, pub_key);
  if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, "pyp11.verify: C_VerifyInit bad");
	return NULL;
  }
  chk_rv = handle->pkcs11->C_Verify(handle->session, digest, digest_len, signature, signature_len);

  //finish:
  handle->pkcs11->C_DestroyObject(handle->session, pub_key);
  free(digest);
  free(signature);
  free(pub_template[3].pValue);
  free(pub_template[4].pValue);
  free(pub_template[9].pValue);
  	
  	
  if (chk_rv != CKR_OK) {
    return(Py_BuildValue("s", "0"));
  } else {
    //fprintf(stderr,"tclpkcs11_perform_pki_verify OK\n");
    return(Py_BuildValue("i", 1));
  }
}

static PyObject *
pyp11_pki_dgst(PyObject *self, PyObject *args) {
/*Usage: pyp11.dgst (<'stribog256'|'stribog512'>, <content>) => digest_hex|NULL */
    int objc;
  GOSTR3411_2012_CTX ctx;
  unsigned char digest[64];
  int rc = 0;

  unsigned char *input;
  char *algohash;
//  int input_len;
  Py_ssize_t input_len = 0;
  PyObject *tcl_mode, *tcl_input;
  PyObject *tcl_result;
  int lenhash;
  objc = PyTuple_Size(args);
  if (objc != 2) {
        PyErr_SetString(PyExc_TypeError, "pki_dgst args error (count args != 2): pyp11.dgst (<'stribog256'|'stribog512'>, <content>)");
	return NULL;
  }
  PyArg_ParseTuple(args, "OO", &tcl_mode, &tcl_input);

  PyArg_Parse(tcl_input, "s#", &input, &input_len);
  PyArg_Parse(tcl_mode, "s", &algohash);
  if (!memcmp("stribog256", algohash, 10)) {
    lenhash = 32;
  } else if (!memcmp("stribog512", algohash, 10)) {
    lenhash = 64;
  } else {
        PyErr_SetString(PyExc_TypeError, "\"pyp11.dgst ('stribog256'|'stribog512', <content>\" - bad digest");
	return NULL;
  }
  rc = GOSTR3411_2012_Init(&ctx, lenhash);
  if (rc != 0) {
        PyErr_SetString(PyExc_TypeError, "\"pyp11.dgst ('stribog256'|'stribog512', <content>\" - bad GOSTR3411_2012_Init stribog");
	return NULL;
  }
  rc = GOSTR3411_2012_Update(&ctx, input, input_len);
  if (rc != 0) {
        PyErr_SetString(PyExc_TypeError, "\"pyp11.dgst ('stribog256'|'stribog512', <content>\" - GOSTR3411_2012_Update failed");
	return NULL;
  }
  rc = GOSTR3411_2012_Final(&ctx, digest);
  if (rc != 0) {
        PyErr_SetString(PyExc_TypeError, "\"pyp11.dgst ('stribog256'|'stribog512', <content>\" - GOSTR3411_2012_Final failed");
	return NULL;
  }
  /* Convert the ID into a readable string */
  tcl_result = tclpkcs11_bytearray_to_string(digest, lenhash);

  return (tcl_result);
}

static PyObject *
pyp11_inittoken(PyObject *self, PyObject *args) {
/*Usage: pyp11.inittoken (<handle>, <slot>, <SO-pin kod>, <token_label>) => 1|NULL */
    extern struct tclpkcs11_interpdata *cd;
    int objc;
  struct tclpkcs11_interpdata *interpdata;
  struct tclpkcs11_handle *handle;
  PyObject *tcl_password, *tcl_tokenlab;
  char *tcl_handle;
  Py_ssize_t slotid_long = 0;
  char *password;
//  int password_len;
  Py_ssize_t password_len = 0;
  CK_UTF8CHAR     label[32];        // What we want to set the Label of the card to
  char*  enteredlabel; // Max size of 32 + carriage return;
//  int label_len;
  Py_ssize_t label_len = 0;

  CK_SLOT_ID slotid;
  CK_RV chk_rv;
  PyObject *hh;

  if (!cd) {
        PyErr_SetString(PyExc_TypeError, "pki_inittoken: invalid hash_table");
	return NULL;
  }
  objc = PyTuple_Size(args);
  if (objc != 4) {
        PyErr_SetString(PyExc_TypeError, "pki_inittoken args error (count args != 4): pyp11.inittoken (<handle>, <slot>, <SO-PIN kod>, <token_label>)");
	return NULL;
  }
  PyArg_ParseTuple(args, "slOO", &tcl_handle, &slotid_long, &tcl_password, &tcl_tokenlab);
  interpdata = (struct tclpkcs11_interpdata *) cd;
  hh =  PyDict_GetItemString(interpdata->handles, tcl_handle);
  if (hh == NULL) {
        PyErr_SetString(PyExc_TypeError, "pyp11.inittoken: invalid handle module)");
	return NULL;
  }
  tclpkcs11_string_to_bytearray(hh, (unsigned char *)&handle, sizeof(handle));

  if (!handle) {
        PyErr_SetString(PyExc_TypeError, "pyp11.inittoken: 2 invalid handle module");
	return NULL;
  }
    slotid = slotid_long;

  PyArg_Parse(tcl_password, "s#", &password, &password_len);
  PyArg_Parse(tcl_tokenlab, "s#", &enteredlabel, &label_len);
  memset(label, ' ', sizeof(label));
  memcpy(label, enteredlabel, label_len);

  tclpkcs11_close_session(handle);

  chk_rv = handle->pkcs11->C_InitToken(slotid, (CK_UTF8CHAR_PTR) password, password_len, label);
  switch (chk_rv) {
    case CKR_OK:
      break;
    case CKR_PIN_INCORRECT:
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
    default:
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
  }

  return(Py_BuildValue("i", 1));
}

static PyObject *
pyp11_inituserpin(PyObject *self, PyObject *args) {
/*Usage: pyp11.inituserpin (<handle>, <slot>, <SO-pin kod>, <token_label>) => 1|NULL */
    extern struct tclpkcs11_interpdata *cd;
    int objc;
  struct tclpkcs11_interpdata *interpdata;
  struct tclpkcs11_handle *handle;
  PyObject *tcl_sopin, *tcl_userpin;
  char *tcl_handle;
  Py_ssize_t slotid_long = 0;
  char *sopin;
//  int sopin_len;
  Py_ssize_t sopin_len = 0;
  char *userpin;
//  int userpin_len;
  Py_ssize_t userpin_len = 0;

  CK_SLOT_ID slotid;
  CK_RV chk_rv;
  CK_RV chk1_rv;
  PyObject *hh;

  if (!cd) {
        PyErr_SetString(PyExc_TypeError, "pki_inituserpin: invalid hash_table");
	return NULL;
  }
  objc = PyTuple_Size(args);
  if (objc != 4) {
        PyErr_SetString(PyExc_TypeError, "pki_inituserpin args error (count args != 4): pyp11.inittoken (<handle>, <slot>, <SO-PIN code>, <USER-PIN code>)");
	return NULL;
  }
  PyArg_ParseTuple(args, "slOO", &tcl_handle, &slotid_long, &tcl_sopin, &tcl_userpin);
  interpdata = (struct tclpkcs11_interpdata *) cd;
  hh =  PyDict_GetItemString(interpdata->handles, tcl_handle);
  if (hh == NULL) {
        PyErr_SetString(PyExc_TypeError, "pyp11.inituserpin: invalid handle module)");
	return NULL;
  }
  tclpkcs11_string_to_bytearray(hh, (unsigned char *)&handle, sizeof(handle));

  if (!handle) {
        PyErr_SetString(PyExc_TypeError, "pyp11.inituserpin: 2 invalid handle module");
	return NULL;
  }
    slotid = slotid_long;
    chk_rv = tclpkcs11_start_session(handle, slotid);
    if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
    }

  PyArg_Parse(tcl_sopin, "s#", &sopin, &sopin_len);
  chk_rv = handle->pkcs11->C_Login(handle->session, CKU_SO, (CK_UTF8CHAR_PTR) sopin, sopin_len);
  if (chk_rv != CKR_OK) {
      if (chk_rv == CKR_PIN_INCORRECT) {
        PyErr_SetString(PyExc_TypeError, "pyp11.inituserpin: CKR_PIN_INCORRECT");
	return NULL;
      }
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
  }
  PyArg_Parse(tcl_userpin, "s#", &userpin, &userpin_len);
  chk1_rv = handle->pkcs11->C_InitPIN(handle->session, (CK_UTF8CHAR_PTR) userpin, userpin_len);
  chk_rv = handle->pkcs11->C_Logout(handle->session);
  if (chk_rv != CKR_OK) {
    if (chk_rv == CKR_DEVICE_REMOVED) {
      handle->session_active = 0;

      handle->pkcs11->C_CloseSession(handle->session);
    } else {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
    }
  }
  if (chk1_rv != CKR_OK) {
      if (chk1_rv == CKR_PIN_INCORRECT) {
        PyErr_SetString(PyExc_TypeError, "pyp11.inituserpin 1: CKR_PIN_INCORRECT");
	return NULL;
      }
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
  }

  return(Py_BuildValue("i", 1));
}

static PyObject *
pyp11_setpin(PyObject *self, PyObject *args) {
/*Usage: pyp11.setpin (<handle>, <slot>, <type pin: so|user>, <old pin>, <new pin>) => 1|NULL */
    extern struct tclpkcs11_interpdata *cd;
    int objc;
  struct tclpkcs11_interpdata *interpdata;
  struct tclpkcs11_handle *handle;
  PyObject *tcl_oldpin, *tcl_newpin, *tcl_typepin;
  char *tcl_handle;
  Py_ssize_t slotid_long = 0;
  char *oldpin;
//  int oldpin_len;
  Py_ssize_t oldpin_len = 0;
  char *newpin;
//  int newpin_len;
  Py_ssize_t newpin_len = 0;
  char *typepin;
//  int typepin_len;
  Py_ssize_t typepin_len = 0;

  CK_SLOT_ID slotid;
  CK_RV chk_rv;
  CK_RV chk1_rv;
  PyObject *hh;

  if (!cd) {
        PyErr_SetString(PyExc_TypeError, "pki_setpin: invalid hash_table");
	return NULL;
  }
  objc = PyTuple_Size(args);
  if (objc != 5) {
        PyErr_SetString(PyExc_TypeError, "pki_setpin args error (count args != 5): pyp11.setpin (<handle>, <slot>, <type pin: so|user>, <old pin>, <new pin>)");
	return NULL;
  }
  PyArg_ParseTuple(args, "slOOO", &tcl_handle, &slotid_long, &tcl_typepin, &tcl_oldpin, &tcl_newpin);
  interpdata = (struct tclpkcs11_interpdata *) cd;
  hh =  PyDict_GetItemString(interpdata->handles, tcl_handle);
  if (hh == NULL) {
        PyErr_SetString(PyExc_TypeError, "pyp11.setpin: invalid handle module)");
	return NULL;
  }
  tclpkcs11_string_to_bytearray(hh, (unsigned char *)&handle, sizeof(handle));

  if (!handle) {
        PyErr_SetString(PyExc_TypeError, "pyp11.setpin: 2 invalid handle module");
	return NULL;
  }
    slotid = slotid_long;
    chk_rv = tclpkcs11_start_session(handle, slotid);
    if (chk_rv != CKR_OK) {
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
    }
//===============
  PyArg_Parse(tcl_typepin, "s#", &typepin, &typepin_len);
  PyArg_Parse(tcl_oldpin, "s#", &oldpin, &oldpin_len);
  if (typepin_len == 2 && !memcmp(typepin, "so", 2)) {
    chk_rv = handle->pkcs11->C_Login(handle->session, CKU_SO, (CK_UTF8CHAR_PTR) oldpin, oldpin_len);
  } else if (typepin_len == 4 && !memcmp(typepin, "user", 4)) {
    chk_rv = handle->pkcs11->C_Login(handle->session, CKU_USER, (CK_UTF8CHAR_PTR) oldpin, oldpin_len);
  } else {
        PyErr_SetString(PyExc_TypeError, "pyp11.setpin: bad type (so or user)");
	return NULL;
  }
  if (chk_rv != CKR_OK) {
      if (chk_rv == CKR_PIN_INCORRECT) {
        PyErr_SetString(PyExc_TypeError, "pyp11.setpin: CKR_PIN_INCORRECT");
	return NULL;
      }
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
  }
  PyArg_Parse(tcl_newpin, "s#", &newpin, &newpin_len);
  chk1_rv = handle->pkcs11->C_SetPIN(handle->session, (CK_UTF8CHAR_PTR)oldpin, oldpin_len, (CK_UTF8CHAR_PTR)newpin, newpin_len);

  handle->pkcs11->C_CloseSession(handle->session);

  if (chk1_rv != CKR_OK) {
      if (chk1_rv == CKR_PIN_INCORRECT) {
        PyErr_SetString(PyExc_TypeError, "pyp11.setpin: CKR_PIN_INCORRECT");
	return NULL;
      }
        PyErr_SetString(PyExc_TypeError, tclpkcs11_pkcs11_error(chk_rv));
	return NULL;
  }

  return(Py_BuildValue("i", 1));
}


//Док-ция для loadmodule
//static char  * const python_methods_docs[] = {
static char  const python_methods_docs[][200] = {
    "loadmodule(<path to library PKCS11>): identifiee library",
    "unloadmodule(<handle lib>): unload library PKCS11",
    "list_slots(<handle lib>): list info slots",
    "listmechs(<handle lib>, <slotid>): list mechanisms token",
    "listcerts(<handle lib>, <slotid>): list certififates from token",
    "list_objects(<handle lib>, <slotid>, <type object> [, 'value']): list objects from token",
    "login(<handle lib>, <slotid>, <password>): true|false",
    "logout(<handle lib>, <slotid>): true|false",
    "digest(<handle lib>, <slotid>, <algo digest>, <content>): digest_hex",
    "keypair(<handle lib>, <slotid>, <algo key>, <param key (gostr3410)>, [<cka_label>]) => dict",
    "importcert (<handle lib>, <slotid>, <cert_der to hex>) => <pkcs11_id to hex>",
    "pubkeyinfo ([<handle lib>, <slotid>,] <cert_der to hex>) => dict",
    "closesession (<handle lib>) => 1|NULL",
    "delete (<handle lib>, <slotid>, <dict>) => 1|NULL",
    "rename (<handle lib>, <slotid>, <dict>) => 1|NULL",
    "sign (<handle lib>, <slotid>, <\"CKM_GOSTR3410_512\"|\"CKM_GOSTR3410\">, <digest_hex>, <pkcs11_id|hobj_privkey>) => signature",
    "verify (<handle lib>, <slotid>, <digest_hex>, <signature_hex_hex>, <pubkeyinfo_hex>) => 1| NULL",
    "dgst(<'stribog256'|'stribog512'>, <content>): => digest_hex",
    "inittoken(<handle lib>, <slotid>, <SO-PIN code>, <token_label>): => 1|NULL",
    "inituserpin(<handle lib>, <slotid>, <SO-PIN code>, <USER-PIN code>): => 1|NULL",
    "setpin(<handle lib>, <slotid>, <SO-PIN code>, <type PIN: 'so'|'user'>, <old PIN>, <new PIN>): => 1|NULL",
    "importkey (<handle lib>, <slotid>, <dict for keypair>) => 1|NULL",
};
// Список функций модуля
static PyMethodDef methods[] = {
    {"loadmodule", pyp11_load_module, METH_VARARGS, python_methods_docs[0]}, // Функция загрузки библиотеки PKCS#11
    {"unloadmodule", pyp11_unload_module, METH_VARARGS, python_methods_docs[1]}, // Функция выгрузки библиотеки PKCS#11
    {"listslots", pyp11_list_slots, METH_VARARGS, python_methods_docs[2]}, // Функция выгрузки библиотеки PKCS#11}
    {"listmechs", pyp11_listmechs, METH_VARARGS, python_methods_docs[3]}, //Список механизмов токена, установленного в слоте
    {"listcerts", pyp11_list_certs_der, METH_VARARGS, python_methods_docs[4]}, //Список сертификатов на токена, установленном в слоте
    {"listobjects", pyp11_list_objects, METH_VARARGS, python_methods_docs[5]}, //Список объектов на токена, установленном в слоте
    {"login", pyp11_login, METH_VARARGS, python_methods_docs[6]}, //Логин на токена, установленном в слоте
    {"logout", pyp11_logout, METH_VARARGS, python_methods_docs[7]}, //Логоут с токена, установленном в слоте
    {"digest", pyp11_digest, METH_VARARGS, python_methods_docs[8]}, //Считаем и возвращвем хэш
    {"keypair", pyp11_keypair, METH_VARARGS, python_methods_docs[9]}, //Генерация ключевой пары
    {"importcert", pyp11_importcert, METH_VARARGS, python_methods_docs[10]}, //Импорт на токен сертификата
    {"parsecert", pyp11_parsecert, METH_VARARGS, python_methods_docs[11]}, //Информация по сертификату
    {"closesession", pyp11_closesession, METH_VARARGS, python_methods_docs[12]}, //Импорт на токен сертификата
    {"delete", pyp11_delete, METH_VARARGS, python_methods_docs[13]}, //Удаление объекта (сертификат, ключевая пара)
    {"rename", pyp11_rename, METH_VARARGS, python_methods_docs[14]}, //Переименование объекта (сертификат, ключевая пара)
    {"sign", pyp11_pki_sign, METH_VARARGS, python_methods_docs[15]}, //Подписать хэш
    {"verify", pyp11_pki_verify, METH_VARARGS, python_methods_docs[16]}, //Подписать хэш
    {"dgst", pyp11_pki_dgst, METH_VARARGS, python_methods_docs[17]}, //Посчитать хэш по stribog256 или stribog512
    {"inittoken", pyp11_inittoken, METH_VARARGS, python_methods_docs[18]}, //Инициализация токена
    {"inituserpin", pyp11_inituserpin, METH_VARARGS, python_methods_docs[19]}, //Инициализация токена
    {"setpin", pyp11_setpin, METH_VARARGS, python_methods_docs[20]}, //Установить PIN
    {"importkey", pyp11_pki_importkey, METH_VARARGS, python_methods_docs[21]}, //Импорт на токен сертификата
    {NULL, NULL, 0, NULL}
};

// Описание модуля
static struct PyModuleDef module = {
    PyModuleDef_HEAD_INIT, "pyp11", "fuctions PKCS11", -1, methods
};

// Инициализация модуля
PyMODINIT_FUNC 
PyInit_pyp11(void) {
    extern struct tclpkcs11_interpdata *cd;
    cd = (struct tclpkcs11_interpdata *) malloc(sizeof(struct tclpkcs11_interpdata));
    cd->handles = PyDict_New();
    cd->handles_idx = 0;
//fprintf (stderr, "INIT OK\n");

    PyObject *mod = PyModule_Create(&module);
    return mod;
}
