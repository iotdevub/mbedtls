#ifndef __UONEK_MBEDTLS_H__
#define __UONEK_MBEDTLS_H__

#include "uonek_dtls.h"
#include "mbedtls/ssl.h"

#ifdef UONEK_MBEDTLS_IMPORT_KEY
int uonek_mbedtls_export_keys( void *p_expkey,
                               const unsigned char *ms,
                               const unsigned char *kb,
                               size_t maclen,
                               size_t keylen,
                               size_t ivlen );

int uonek_mbedtls_export_ext_keys( void *p_expkey,
                                   const unsigned char *ms,
                                   const unsigned char *kb,
                                   size_t maclen,
                                   size_t keylen,
                                   size_t ivlen,
                                   const unsigned char client_random[32],
                                   const unsigned char server_random[32],
                                   mbedtls_tls_prf_types tls_prf_type );
#endif

#endif /* __UONEK_MBEDTLS_H__ */
