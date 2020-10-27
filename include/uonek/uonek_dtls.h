/**
 * \file uonek_dtls.h
 *
 * \~Korean
 * \brief   이 파일은 UONEK 가 DTLS 기능의 보안 부분을 지원하기 위한 API 를 정의한 header 파일이다. 
 * 
 * \~Korean-en
 * \brief   This file has several API for supporting security feature of DTLS
 * 
 */

#ifndef __UONEK_DTLS_H__
#define __UONEK_DTLS_H__

#include "uonek_type.h"
#include "uonek_const.h"
//#include "uonek_dlms.h"

#ifdef  __cplusplus
extern "C" {
#endif

/*** this is from https://tls.mbed.org/kb/how-to/mbedtls-tutorial
SSL/TLS
The SSL/TLS part of Mbed TLS provides the means to set up and communicate over a secure communication channel using SSL/TLS.

Its basic functionalities are:
    Initialize an SSL/TLS context.
    Perform an SSL/TLS handshake.
    Send/receive data.
    Notify a peer that a connection is being closed.

Many aspects of such a channel are set through parameters and callback functions:
    The endpoint role: client or server.
    The authentication mode: to state whether certificate verification is needed or not.
    The host-to-host communication channel: send and receive functions.
    The random number generator (RNG) function.
    The ciphers to use for encryption/decryption.
    A certificate verification function.
    Session control: session get and set functions.
    X.509 parameters for certificate handling and key exchange.

Setup
SSL Connection
Configuring SSL/TLS
Now that the low level socket connection is up and running, you need to configure the SSL/TLS layer.
    1. Prepare the SSL configuration by setting the endpoint and transport type, and loading reasonable defaults for the security parameters.
    2. Set the authentication mode. It determines how strictly the certificates are checked. For this tutorial, we are not checking anything.
    3. Set the random engine and debug function. The library needs to know what to use as callback.
    4. For the debug function to work, add a debug callback called my_debug above our main() function.
    5. Now that the configuration is ready, set up the SSL context to use it.
    6. Finally, the SSL context needs to know the input and output functions it needs to use for sending out network traffic
Reading and writing data
    write -> while( ( ret = mbedtls_ssl_write( &ssl, buf, len ) ) <= 0 )
    read  -> ret = mbedtls_ssl_read( &ssl, buf, len );
Server (and client) authentication
    mbedtls_x509_crt_init( &cacert );
    ret = mbedtls_x509_crt_parse_file( &cacert, cafile );
    mbedtls_ssl_conf_ca_chain( &conf, &cacert, NULL );
    mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_REQUIRED );
Teardown
    mbedtls_net_free( &server_fd );
    mbedtls_ssl_free( &ssl );
    mbedtls_ssl_config_free( &conf );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
*/

/*** API header from ssl.h    
mbedtls's configuration API before hs (handshake) or during hs
  *api* means we should export
  _api_ means we should internally set and use
      mbedtls_ssl_conf_endpoint - which program, server or client    
      mbedtls_ssl_conf_transport - TLS or DTLS
      mbedtls_ssl_conf_authmode - VERIFY or OPTION or NONE
      mbedtls_ssl_conf_verify - user's callback of certi verify
      *mbedtls_ssl_conf_rng* - set random function pointer
      mbedtls_ssl_conf_dbg
      *mbedtls_ssl_set_bio* - binary I/O callback, send, recv, recv_timeout
      _mbedtls_ssl_set_mtu_ - set max datagram playload of DTLS
      mbedtls_ssl_conf_read_timeout - set timeout value of recv_timeout
      mbedtls_ssl_set_timer_cb - need at DTLS
      MBEDTLS_SSL_EXPORT_KEYS feature is needed for EAP-TLS
      mbedtls_ssl_conf_dtls_cookies - ?
      mbedtls_ssl_set_client_transport_id - DTLS server only
      mbedtls_ssl_conf_dtls_anti_replay - DTLS
      mbedtls_ssl_conf_dtls_badmac_limit - DTLS
      mbedtls_ssl_conf_handshake_timeout - DTLS    
      mbedtls_ssl_conf_ciphersuites - example at "ssl_server2.c"
      *mbedtls_ssl_conf_ca_chain* - set CA certi
      *mbedtls_ssl_conf_own_cert* - set my certi, ex at "dtls_server.c"
      *mbedtls_ssl_conf_psk* - set PSK and id name
      mbedtls_ssl_conf_psk_cb - psk setting callback function pointer
        mbedtls_ssl_set_hs_psk - set current handshake's PSK
      mbedtls_ssl_set_hostname
      _mbedtls_ssl_conf_max_version_ - set max supporting version
      _mbedtls_ssl_conf_min_version_ - set min supporting version
      mbedtls_ssl_conf_sni - Server Name Indication (server side)
      mbedtls_ssl_set_hs_own_cert - set own certi in SNI callback,
                                    
                                    like mbedtls_ssl_conf_own_cert
      mbedtls_ssl_set_hs_ca_chain
      mbedtls_ssl_set_hs_authmode
      mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_OPTIONAL );
      mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
      mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );
      mbedtls_ssl_conf_handshake_timeout
    
 mbedtls core api
      mbedtls_ssl_get_peer_cert    
      mbedtls_ssl_handshake
      mbedtls_ssl_read
      mbedtls_ssl_write
      _mbedtls_ssl_config_defaults_ - we should make config_uonek
*/    
    
// mbedtls_ssl_write_certificate should get certificate from SE
//    to send to client from server.
//  --> mbedtls_ssl_write_certificate should be changed
//    --> mbedtls_ssl_own_cert
//      --> struct mbedtls_ssl_handshake_params's mbedtls_ssl_key_cert *key_cert
//          ^-- ssl_handshake_params_init has no code for this
//          ^-- ssl_pick_cert's list is from ssl->conf->key_cert
//   or --> struct mbedtls_ssl_key_cert's mbedtls_ssl_key_cert *key_cert
//          ^-- mbedtls_ssl_conf_ca_chain( &conf, &cacert, NULL )         
//    ==> ssl->conf->key_cert will have SE's cert data
//    so mbedtls_ssl_setup( &ssl, &conf ) is spot we want
//    conf is most important I think.
//    this is setup at main function of client and server

#define UONEK_FEATURE_SUPPORT_DTLS    
#define UONEK_MBEDTLS_IMPORT_KEY
    
sint32 uonek_dtls_save_psk(uint16 index, const uint8 *psk, uint16 size);
sint32 uonek_dtls_save_sharedz(uint16 index, const uint8* sharedz, uint16 size);
sint32 uonek_dtls_save_prf_data(uint16 index, const uint8* prf_data, uint16 size);
sint32 uonek_dtls_save_prf_keys(uint16 index, const uint8** prf_keys, uint16 key_num, uint16 size);

sint32 uonek_dtls_load_psk(uint16 index, uint8 *psk, uint16 *size);
sint32 uonek_dtls_load_sharedz(uint16 index, uint8* sharedz, uint16 *size);
sint32 uonek_dtls_load_prf_data(uint16 index, uint8* prf_data, uint16 *size);

// remove is not needed, because SE could overwrite data
//sint32 uonek_dtls_remove_psk(uint16 index, uint8 *psk, uint16 *size);
//sint32 uonek_dtls_remove_sharedz(uint16 index, uint8* sharedz, uint16 *size);
//sint32 uonek_dtls_remove_prf_data(uint16 index, uint8* prf_data, uint16 *size);

sint32 uonek_dtls_ka_kdf();

sint32 uonek_dtls_psk_encipher();
sint32 uonek_dtls_psk_decipher();

sint32 uonek_dtls_EK_encipher();
sint32 uonek_dtls_EK_decipher();

#ifdef  __cplusplus
}
#endif


#endif /* __UONEK_DTLS_H__ */
