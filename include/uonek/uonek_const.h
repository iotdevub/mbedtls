/**
 * \file uonek_const.h
 *
 * \~Korean
 * \brief   이 파일은 UONEK 상수들에 대한 정의를 포함한다.
 *
 * \~Korean-en 
 * \brief   This file contains UONEK @b constants definitions.
 *
 */

#ifndef __UONEK_CONST_H__
#define __UONEK_CONST_H__
// 한글 가능

/** Maximum number of symmetric key set */
//FIXME not include 32 so UONEK_NUM_OF_SYM_KEY_SET is much more accurate.
#define UONEK_MAX_SYM_KEY_SET 32
/** Maximum number of asymmetric key slot */
//FIXME max means [0..max] but below means [0..max)
// if (0..max), UONEK_NUM_OF_ASYM_KEY_SLOT rather than below
#define UONEK_MAX_ASYM_KEY_SLOT (UONEK_MAX_SYM_KEY_SET + 6)

#define UONEK_ECP_PUB_SIZE 65       /**< ECP public key size in byte. */
#define UONEK_ECP_PRI_SIZE 32       /**< ECP private key size in byte. */
#define UONEK_ECP_PUB_PEM_SIZE 125  /**< Size of ECP public key and PEM certificate. */
#define UONEK_ECP_PRI_PEM_SIZE 166  /**< Size of ECP private key and PEM certificate. */
#define UONEK_SYM_HMAC_SIZE 32      /**< HMAC key size.*/
#define UONEK_SYM_AES_SIZE 16       /**< AES key size. */
#define UONEK_SYM_ARIA_SIZE 16      /**< ARIA key size. */
#define UONEK_SHARED_SECRET_SIZE 32 /**< Shared secret key size. */
#define UONEK_ALG_ID_SIZE 7         /**< Alogrithm Identifier size. */
#define UONEK_KDF_SIZE 32           /**< Key Derivation Function size. */

#define UONEK_SYSTEM_TITLE_SIZE 8   /**< System title size. */
#define UONEK_AA_CHALLENGE_SIZE 32  /**< Application Association Challenge size. */
#define UONEK_AA_SIGNATURE_SIZE 0x40/**< Application Association Signature size. */
#define UONEK_SYSTEM_PIN_SIZE 16    /**< System pin size. */
#define UONEK_HMAC_SHA256_SIGN_SIZE 32
#define UONEK_HASH_SHA256_SIZE 32
// this is temporary max value
#define UONEK_MAX_X509_CERT_SIZE 797 /**< Maximum size of X.509 certificate. */

#define UONEK_GCM_TAG_SIZE       12   /**< GCM Tag length */
#define UONEK_GCM_IC_SIZE        4    /**< IC size */

#define UONEK_DRV_VERSION_SIZE   3    /**< driver version size */
#define UONEK_RELEASE_DATE_SIZE  3    /**< release date size */
#define UONEK_SE_SERIAL_SIZE     8    /**< SE serial nuber size */
#define UONEK_SE_FIRM_VER_SIZE   3    /**< SE FW version size */
#define UONEK_SE_APP_VER_SIZE    3    /**< SE APP version size */ 

#define UONEK_SE_PIN_TRY_MAX     0x0f /**< SE pin try count */

#define UONEK_SECURITY_LOG_MAX_SIZE 0x50

// FIXME this value is not fixed, it could be changed later
#define UONEK_MAX_PSK_NUM 4
#define UONEK_KEPCO_PSK_SIZE 16
#define UONEK_MAX_PRF_NUM (128 + 4) // nvm 128 + ram 4
#define UONEK_KEPCO_PRF_SIZE 64 // 16 * 4
#define UONEK_MAX_SHZ_NUM (128 + 4) // nvm 128 + ram 4
#define UONEK_KEPCO_SHZ_SIZE 32

#endif /* __UONEK_CONST_H__ */
