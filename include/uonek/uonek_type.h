/**
 * \file uonek_type.h
 *
 * \~Korean
 * \brief   이 파일은 UONEK 타입들에 대한 정의를 포함한다.
 *
 * \~Korean-en
 * \brief   This file contains UONEK @b types definitions.
 *
 */

#ifndef __UONEK_TYPE_H__
#define __UONEK_TYPE_H__


// primitive type definition

#ifndef _STDINT_H
#include <stdint.h>
#endif

#if 0
typedef unsigned char           uint8;
typedef unsigned short          uint16;
typedef unsigned long int       uint32;
typedef unsigned long long int  uint64;
typedef char                    sint8;
typedef short                   sint16;
typedef long int                sint32;
typedef long long int           sint64;
typedef unsigned char           bool;
#else
#define uint8   uint8_t
#define uint16  uint16_t
#define uint32  uint32_t
//#define uint64  uint64_t
#define sint8   int8_t
#define sint16  int16_t
#define sint32  int32_t
//#define sint64  int64_t
#endif


 
//resource index type definition

//typedef uint8   uonek_certi_idx;
//typedef uint8   uonek_key_idx;
//typedef uint16  uonek_key_type;

/**
 * \~Korean
 * \brief     DLMS 키 종류를 규격에 있는 순서대로 id 값을 정의함.
 * \~Korean-en
 * \brief     Define key id value of DLMS keys according to DLMS specification
 */
typedef enum uonek_dlms_gkey_id {
    // mapping with UONEK spec doc
    DLMS_KEY_MK,   /**< DLMS KEK(Key Encryption Key). */
    DLMS_KEY_GUEK, /**< DLMS Global Unicast Encryption Key. */
    DLMS_KEY_GBEK, /**< DLMS Global Broadcast Encryption Key. */
    DLMS_KEY_GAK,  /**< DLMS Global Authentication Key. */
    DLMS_KEY_DEK,  /**< DLMS Dedicated Encryption Key. */
    DLMS_KEY_PWD,  /**< DLMS LLS's Password. (Low Level Security). */
    DLMS_KEY_ECK,  /**< DLMS Ephermaral Client Encryption Key. */
    DLMS_KEY_ESK,  /**< DLMS Ephermaral Server Encryption Key. */
    DLMS_GLOBALKEY_LAST, /**< DLMS Last Global key. */
    DLMS_KEY_OTHER, /**< DLMS other key. */

#if 0 // DTLS key could be defined as other enum
    DTLS_KEY_PSK,
    DTLS_KEY_PRF,
    DTLS_KEY_SHAREDZ,
#endif
} uonek_dlms_gkey_id;

/**
 * \~Korean
 * \brief     UONEK 데이터 타입들을 정의함.
 * \~Korean-en
 * \brief     Supported data types.
*/
typedef enum uonek_data_type {
    // for cert type, and for key purpose 
    UONEK_CERT_CA       = 0x00, /**< CA type of certificate. */ // 0000_0000
    UONEK_CERT_RA       = 0x01, /**< RA type of certificate. */ // 0000_0001
    UONEK_CERT_DSA      = 0x02, /**< DSA type of certificate. */ // 0000_0010
    UONEK_CERT_DH       = 0x04, /**< DH type of certificate. */ // 0000_0100
    UONEK_CERT_EDH      = 0x08, /**< EDH type of certificate. */ // 0000_1000
    UONEK_CERT_UNKNOWN  = 0x0F, /**< Unknown type of certificate. */
    UONEK_CERT_TYPE_MASK= 0x0F, /**< Mask of certificate type*/

    // key types
    UONEK_KEY_ECP_PUB   = 0x10, /**< ECP Public key. */  // 0001_0000
    UONEK_KEY_ECP_PRI   = 0x20, /**< ECP Private key. */ // 0010_0000
#if 0
    UONEK_KEY_RSA_PUB   = 0x50, /**< RSA Public key. */  // 0101_0000
    UONEK_KEY_RSA_PRI   = 0x60, /**< RSA Private key. */ // 0110_0000
#endif
    UONEK_KEY_SYM_ARIA  = 0x80, /**< ARIA key. */ // 1000_0000
    UONEK_KEY_SYM_AES   = 0x90, /**< AES key. */  // 1001_0000
    UONEK_KEY_HMAC      = 0xA0, /**< HMAC key. */ // 1010_0000
    UONEK_KEY_UKEK      = 0xB0, /**< UKEK key */  // 1011_0000
#if 1 // types for DTLS
    UONEK_KEY_PSK       = 0xC0, /**< PSK key */   // 1100_0000
    UONEK_KEY_PRF       = 0xD0, /**< keys after PRF */          // 1101_0000
    UONEK_KEY_SHAREDZ   = 0xE0, /**< shared Z value after DH */ // 1110_0000
#endif

    UONEK_KEY_TYPE_MASK = 0xF0, /**< Mask of certificate type. */

    // for store info data
    UONEK_INFO_SYSTEM_TITLE = 0xF1, /**< System title info. */ // 1111_1001
    UONEK_INFO_SYSTEM_PIN = 0xF2,   /**< System pin info. */   // 1111_1001
    UONEK_INFO_SYSTEM_INFO = 0xF3,  /**< System info ??. */
    UONEK_INFO_TYPE_MASK= 0xF8,     /**< Info type mask. */
    
    // for param of generate key pair
    UONEK_FOR_CA        = (UONEK_CERT_CA|UONEK_KEY_ECP_PUB),   /**< CA type of public key. */
    UONEK_FOR_RA        = (UONEK_CERT_RA|UONEK_KEY_ECP_PUB),   /**< RA type of public key. */
    UONEK_FOR_DSA       = (UONEK_CERT_DSA|UONEK_KEY_ECP_PUB),  /**< DSA type of public key. */
    UONEK_FOR_DH        = (UONEK_CERT_DH|UONEK_KEY_ECP_PUB),   /**< DH type of public key. */
    UONEK_FOR_EDH       = (UONEK_CERT_EDH|UONEK_KEY_ECP_PUB),  /**< EDH type of public key. */
    // for param of ?
    UONEK_PRI_DSA       = (UONEK_CERT_DSA|UONEK_KEY_ECP_PRI),  /**< DSA type of private key. */  // to flash
    UONEK_PRI_DH        = (UONEK_CERT_DH|UONEK_KEY_ECP_PRI),   /**< DH type of private key. */  // to flash 
    UONEK_PRI_EDH       = (UONEK_CERT_EDH|UONEK_KEY_ECP_PRI),  /**< EDH type of private key. */  // ephermaral to ram
    // not sure about below
    UONEK_PRI_DH_AES    = (UONEK_CERT_DH|UONEK_KEY_SYM_AES|UONEK_KEY_ECP_PRI),   /**< DH_AES type of private key. */
    UONEK_PRI_DH_ARIA   = (UONEK_CERT_DH|UONEK_KEY_SYM_ARIA|UONEK_KEY_ECP_PRI),  /**< DH_ARIA type of private key. */
    UONEK_PRI_DSA_AES   = (UONEK_CERT_DSA|UONEK_KEY_SYM_AES|UONEK_KEY_ECP_PRI),  /**< DSA_AES type of private key. */
    UONEK_PRI_DSA_ARIA  = (UONEK_CERT_DSA|UONEK_KEY_SYM_ARIA|UONEK_KEY_ECP_PRI), /**< DSA_ARIA type of private key. */
    UONEK_PRI_EDH_AES   = (UONEK_CERT_EDH|UONEK_KEY_SYM_AES|UONEK_KEY_ECP_PRI),  /**< EDH_AES type of private key. */
    UONEK_PRI_EDH_ARIA  = (UONEK_CERT_EDH|UONEK_KEY_SYM_ARIA|UONEK_KEY_ECP_PRI), /**< EDH_ARIA type of private key. */

} uonek_data_type;

/**
 * \~Korean
 * \brief     지원되는 인증서 필드들을 정의함.
 * \~Korean-en
 * \brief     Supported fields to get from certificate.
*/
typedef enum {
              UONEK_CERTI_FIELD_SN = 1,      /**< Serial Number. */
              UONEK_CERTI_FIELD_ISSUER_CN,   /**< Issuer Name. */
              UONEK_CERTI_FIELD_VALIDITY,    /**< Validity period. */
              UONEK_CERTI_FIELD_SUBJ_CN,     /**< Subject Name. */
              UONEK_CERTI_FIELD_SUBJ_PUBKEY, /**< Subject Public Key. */
              UONEK_CERTI_FIELD_AUTH_KEY_ID, /**< Authority key identifier(Extension). */ //Not implemented yet
              UONEK_CERTI_FIELD_SUBJ_KEY_ID, /**< Subject key identifier(Extension). */   //Not implemented yet
              UONEK_CERTI_FIELD_KEY_USAGE,   /**< Key usage(Extension). */
              UONEK_CERTI_FIELD_BC,          /**< Basic Constraint(Extension). */
              UONEK_CERTI_FIELD_END          /**< Only the above fields are supported. */
}uonek_certi_field;

/**
 * \~Korean
 * \brief     지원되는 해쉬 타입들을 정의함. 
 * \~Korean-en
 * \brief     Supported hash types.
*/
enum uonek_hash_type {
    UONEK_HASH_NO, /**< NO hash. */
    UONEK_HASH_SHA256 = 0x06, /**< SHA256 hash. */
};

enum uonek_hmac_mode {
    UONEK_HMAC_SIGN = 0,
    UONEK_HMAC_VERIFY = 1,
                      
};
/**
 * \~Korean
 * \brief     지원되는 암호 운용방식들을 정의함.
 * \~Korean-en
 * \brief     Supported cipher modes.
*/
enum uonek_cipher_mode {
    UONEK_CIPHER_CBC, /**< CBC mode. */
    UONEK_CIPHER_ECB = 0x06, /**< ECB mode. */
};

/**
 * \~Korean
 * \brief     지원하는 패딩 모드들을 정의함.
 * \~Korean-en
 * \brief     Supported padding modes.
*/
enum uonek_padding_mode {
    UONEK_PADDING_NO, /**< NO padding. */
    UONEK_PADDING_ISO9797_M2 = 0x01, /**< ISO9797_M2 mode. */
};

/**
 * \~Korean
 * \brief     uonek_dlms_put_cert() 함수 호출시 모드를 정의.
 * \~Korean-en
 * \brief     Mode of putting certi operation.
*/
enum uonek_put_certi_mode {
    UONEK_PUT_CERT_ONLY, /**< Put Only certification. */
    UONEK_PUT_CERT_AND_PUBLIC_KEY, /**< Put both certification and public key. */
};

// removed because uonek_data_type should be used
// internal and external is not needed
// because "generate" is internal and "put" is external
// key storage for RAM is "ephermaral" and key storage for Flash is "normal"
#if 0

/**
 * \~Korean
 * \brief     지원하는 EC key 타입.
 * \~Korean-en
 * \brief     Supported EC key type.
*/
enum uonek_ec_key_type {
    UONEK_EC_INTERNAL_DH_PRI,   /**< Internal EC_DH type of private key. */
    UONEK_EC_EXTERNAL_DH_PRI,   /**< External EC_DH type of private key. */
    UONEK_EC_INTERNAL_DH_PUB,   /**< Internal EC_DH type of public key. */
    UONEK_EC_EXTERNAL_DH_PUB,   /**< External EC_DH type of public key. */
    UONEK_EC_INTERNAL_DSA_PRI,  /**< Inetrnal EC_DSA type of private key. */
    UONEK_EC_EXTERNAL_DSA_PRI,  /**< External EC_DSA type of private key. */
    UONEK_EC_INTERNAL_DSA_PUB,  /**< Internal EC_DSA type of public key. */
    UONEK_EC_EXTERNAL_DSA_PUB,  /**< External EC_DSA type of public key. */
    UONEK_EC_KEY_TYPE_END,      /**< Only the above EC key types are supported. */
};
#endif



#define UONEK_KDF_METHOD_MASK     0x01
#define UONEK_SINGLE_STEP_KDF     0x01
#define UONEK_EXTRACT_EXPAND_KDF  0x00

#define UONEK_KDF_HMAC_SHA256_MAKS 0x02
#define UONEK_KDF_HMAC_HASH        0x02
#define UONEK_KDF_SHA2_HASH        0x00

#define UONEK_KEPCO_KDF           0x08 /**< One KDF(32 bytes) store EK(16) and AK(16). */

#define UONEK_KEYAGREEMENT_MASK   0x70
#define UONEK_2E_KDF              0x10
#define UONEK_1E_KDF              0x20
#define UONEK_0E_KDF              0x40


#define UONEK_KDF_KEPCO_2E0S_ECC_CDH                                    \
    (UONEK_2E_KDF | UONEK_SINGLE_STEP_KDF | UONEK_KDF_HMAC_HASH | UONEK_KEPCO_KDF)
#define UONEK_KDF_KEPCO_1E1S_ECC_CDH                                    \
    (UONEK_1E_KDF | UONEK_SINGLE_STEP_KDF | UONEK_KDF_HMAC_HASH | UONEK_KEPCO_KDF)
#define UONEK_KDF_KEPCO_0E2S_ECC_CDH                                    \
    (UONEK_0E_KDF | UONEK_SINGLE_STEP_KDF | UONEK_KDF_HMAC_HASH | UONEK_KEPCO_KDF)


#define UONEK_KDF_DLMS_2E0S_ECC_CDH                                 \
    (UONEK_2E_KDF | UONEK_SINGLE_STEP_KDF | UONEK_SHA256_HASH_KDF)
#define UONEK_KDF_DLMS_1E1S_ECC_CDH                                 \
    (UONEK_1E_KDF | UONEK_SINGLE_STEP_KDF | UONEK_SHA256_HASH_KDF)
#define UONEK_KDF_DLMS_0E2S_ECC_CDH                                 \
    (UONEK_0E_KDF | UONEK_SINGLE_STEP_KDF | UONEK_SHA256_HASH_KDF)


/**
 * \~Korean
 * \brief     DLMS Key ID. ??
 * \~Korean-en
 * \brief     DLMS Key ID.
*/
typedef enum dlms_key_id {
    DLMS_KEPCO_EK_AK_ID = 0, /**< GUEK + GAK. */
    DLMS_GUEK_KEY_ID    = 0, /**< GUEK, Global Unicast Encryption Key. */
    DLMS_GBEK_KEY_ID    = 1, /**< GBEK, Global Broadcasting Encryption Key. */
    DLMS_GAK_KEY_ID     = 2, /**< GAK, Global Authentication Key */
    DLMS_KEK_KEY_ID     = 3, /**< KEK, Key Encryption Master Key */
    DLMS_EEK_S_KEY_ID   = 4, /**< EEK Server, Ephermaral Encryption Key of server */
    DLMS_EEK_C_KEY_ID   = 5, /**< EEK Client, Ephermaral Encryption Key of client */
} dlms_key_id;

#if 0
/**
 * \~Korean
 * \brief     버퍼 구조체.
 * \~Korean-en
 * \brief     Generic buffer.
*/
typedef struct uonek_buffer {
    uint16 len; /**< Length of buffer. */
    uint8 *buf; /**< Buffer for data. */
} uonek_buffer;

/**
 * \~Korean
 * \brief     키 정보 구조체.
 * \~Korean-en
 * \brief     Key Information.
*/
typedef struct uonek_key {
    uint8           key_type; /**< Type of key. */
    uonek_buffer    key_data; /**< Struct for key data. */
} uonek_key;
#endif

#include "uonek_const.h"

/**
 * \~Korean
 * \brief     The version info of UONEK
*/
typedef struct uonek_ver_info {
    uint8 drv_ver[UONEK_DRV_VERSION_SIZE];     /**< The version of UONEK driver */
    uint8 release_date[UONEK_RELEASE_DATE_SIZE]; /**< The release date of UONEK */
    uint8 se_serial_number[UONEK_SE_SERIAL_SIZE]; /**< The serial number of UONEK SE */
    uint8 se_firm_ver[UONEK_SE_FIRM_VER_SIZE]; /**< The firmware version of UONEK SE */
    uint8 se_app_ver[UONEK_SE_APP_VER_SIZE]; /**< The application version of UONEK SE */
} uonek_ver_info;

/**
 * \~Korean
 * \brief     UONEK의 상태.
 * \~Korean-en
 * \brief     Status of UONEK.
*/
enum UONEK_STATUS {
    UONEK_FIRST_BOOTING                 = 2,
    UONEK_VERIFY_FAIL                   = 1,
    UONEK_SUCCESS                       = 0,
    UONEK_ERROR_MASK                    = 0x80000000,
    UONEK_ERROR                         = -1,
    UONEK_ERROR_BAD_PARAM               = -2,
    UONEK_ERROR_NOT_EXIST_SYSTEM_TITLE  = -3,
    UONEK_ERROR_SE_LOCKED               = -4,
    UONEK_ERROR_NOT_IMPLEMENTED_YET     = -5,
    UONEK_ERROR_NOT_SUPPORTED           = -6,
    UONEK_ERROR_NOT_SUPPORT_KEY_INDEX   = -0x6203,
};

/**
 * \~Korean
 * \brief     지원되는 ECDSA 타입.
 * \~Korean-en
 * \brief     Supported ECDSA types.
*/
enum uonek_ecdsa_type {
    ECDSA_P256_SHA256, /**< SHA256. */
    ECDSA_P384_SHA384  /**< SHA384. */
};

enum uonek_hmac_type {
    HMAC_SHA256, /**< SHA256. */
    HMAC_SHA     /**< SHA. */
};


enum uonek_pubkey_flag {
    PUB_KEY_FLAG_UNCOMPRESSED = 0x04,
};

/**
  *  Security log : Cyclic Record
  *  
  *  max count is 200 
  *
  * Cyclic Record example 
  *      1 2 3 4 5
  * 1 :  1 
  * 2 :  2 1
  * 3 :  3 2 1
  * 4 :  4 3 2 1
  * 5 :  5 4 3 2 1
  * 6 :  1 5 4 3 2
  */

typedef enum {
    SE_ERROR_INITIAL =            0xA1,   /**< 암호모듈 초기화 오류 */
    SE_ERROR_LINK    =            0xA2,   /**< 암호모듈 연동 오류 */
    SE_ERROR_CREATE_Z =           0xA3,   /**< Z 생성 오류 */
    SE_ERROR_CREATE_SESSION_KEY = 0xA4,   /**< 세션키 생성 오류 */
    SE_ERROR_ENCRYPT =            0xA5,   /**< 암호화 오류 */
    SE_ERROR_DECRYPT =            0xA6,   /**< 복호화 오류 */
    SE_ERROR_DSA_SIGN =           0xA7,   /**< 전자서명 생성 오류 */
    SE_ERROR_DSA_VERIFY =         0xA8,   /**< 전자서명 검증 오류 */
    SE_ERROR_MISS_SEC_LIST =      0xA9,   /**< 보안항목 오류 */
    SE_ERROR_FAIL_AA       =      0xAA,   /**< 상호인증 실패 */
    SE_ERROR_INSERT_CA_CERTI = 0xB0,      /**< CA인증서 주입 실패 */
    SE_ERROR_INSERT_DS_CERTI = 0xB1,      /**< DS인증서 주입 실패 */
    SE_ERROR_INSERT_KA_CERTI = 0xB2,      /**< KA인증서 주입 실패 */
    SE_ERROR_EXPIRE_CA_CERTI = 0xB3,      /**< CA인증서 만료 */
    SE_ERROR_EXPIRE_DS_CERTI = 0xB4,      /**< CA인증서 만료 */
    SE_ERROR_EXPIRE_KA_CERTI = 0xB5,      /**< CA인증서 만료 */
    SE_ERROR_EXPIRE_PSM_AA = 0xF0,        /**< PSM 상호인증 완료 알림 */
    SE_ERROR_ETC =           0xFF,        /**< 기타(정의되지 않은 오류) */
} uonek_sec_log_tag;

typedef enum  {
    SEC_LOG_PREVIOUS = 0x01,  /**< log가 가득 차 있을 때 맨 처음으로 기록된 log */
    SEC_LOG_CURRENT = 0x02,   /**< 마지막으로 기록된 log */ 
    SEC_LOG_NEXT = 0x03,      /**< 마지막으로 기록된 이전 log */
    SEC_LOG_INDEX   = 0x04,   /**< index가 지정한 log */                           
} uonek_sec_log_mode;


typedef enum {
    SE_ISO7816_CLK_1MHZ = 1000000,
    SE_ISO7816_CLK_2MHZ = 2000000,
    SE_ISO7816_CLK_3MHZ = 3000000,
    SE_ISO7816_CLK_4MHZ = 4000000,
    SE_ISO7816_CLK_5MHZ = 5000000,
} uonek_iso7816_clk;


typedef enum {
    UONEK_SE_SPEED_DEFAULT = 0, // 372 clock for 1 bit sampling
    UONEK_SE_SPEED_128     = 1, // 128 clock for 1 bit sampling
    UONEK_SE_SPEED_128_X2  = 2, // 2 times faster than UONEK_SE_SPEED_128
    UONEK_SE_SPEED_128_X4  = 3, // 4 times fast than UONEK_SE_SPEED_128
    UONEK_SE_SPEED_128_X8  = 4, // 8 times fast than UONEK_SE_SPEED_128
    UONEK_SE_SPEED_128_x16 = 5, // 16 times fast than UONEK_SE_SPEED_128
} uonek_se_uart_speed;

#endif /* __UONEK_TYPE_H__ */
