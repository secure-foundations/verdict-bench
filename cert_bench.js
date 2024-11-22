/**
 * Originally by https://github.com/mozkeeler
 * (https://gist.github.com/mozkeeler/a08d4c6910a23447e6f363df1e563738)
 * 
 * Modified to include some benchmarking code
 */

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// How to run this file:
// 1. [obtain firefox source code]
// 2. [build/obtain firefox binaries]
// 3. run `[path to]/run-mozilla.sh [path to]/xpcshell \
//                                  [path to]/verify.js \
//                                  [path to]/chain.pem

// <https://developer.mozilla.org/en/XPConnect/xpcshell/HOWTO>
// <https://bugzilla.mozilla.org/show_bug.cgi?id=546628>
const Cc = Components.classes;
const Ci = Components.interfaces;
const Cu = Components.utils;
const Cr = Components.results;

let { NetUtil } = Cu.import("resource://gre/modules/NetUtil.jsm", {});
let { Services } = Cu.import("resource://gre/modules/Services.jsm", {});
let { FileUtils } = Cu.import("resource://gre/modules/FileUtils.jsm", {});
let { Promise } = Cu.import("resource://gre/modules/Promise.jsm", {});

const certificateUsageSSLClient         = 0x0001;
const certificateUsageSSLServer         = 0x0002;
const certificateUsageEmailSigner       = 0x0010;
const certificateUsageVerifyCA          = 0x0100;
const certificateUsageAnyCA             = 0x0800;

const ERROR_CODES = new Map([
    // Copied from mozilla-unified/obj-x86_64-pc-linux-gnu/x86_64-unknown-linux-gnu/release/build/neqo-crypto-ddfa555fd025ac0c/out/nss_sslerr.rs
    [-12288, "SSL_ERROR_EXPORT_ONLY_SERVER"],
    [-12287, "SSL_ERROR_US_ONLY_SERVER"],
    [-12286, "SSL_ERROR_NO_CYPHER_OVERLAP"],
    [-12285, "SSL_ERROR_NO_CERTIFICATE"],
    [-12284, "SSL_ERROR_BAD_CERTIFICATE"],
    [-12283, "SSL_ERROR_UNUSED_5"],
    [-12282, "SSL_ERROR_BAD_CLIENT"],
    [-12281, "SSL_ERROR_BAD_SERVER"],
    [-12280, "SSL_ERROR_UNSUPPORTED_CERTIFICATE_TYPE"],
    [-12279, "SSL_ERROR_UNSUPPORTED_VERSION"],
    [-12278, "SSL_ERROR_UNUSED_10"],
    [-12277, "SSL_ERROR_WRONG_CERTIFICATE"],
    [-12276, "SSL_ERROR_BAD_CERT_DOMAIN"],
    [-12275, "SSL_ERROR_POST_WARNING"],
    [-12274, "SSL_ERROR_SSL2_DISABLED"],
    [-12273, "SSL_ERROR_BAD_MAC_READ"],
    [-12272, "SSL_ERROR_BAD_MAC_ALERT"],
    [-12271, "SSL_ERROR_BAD_CERT_ALERT"],
    [-12270, "SSL_ERROR_REVOKED_CERT_ALERT"],
    [-12269, "SSL_ERROR_EXPIRED_CERT_ALERT"],
    [-12268, "SSL_ERROR_SSL_DISABLED"],
    [-12267, "SSL_ERROR_FORTEZZA_PQG"],
    [-12266, "SSL_ERROR_UNKNOWN_CIPHER_SUITE"],
    [-12265, "SSL_ERROR_NO_CIPHERS_SUPPORTED"],
    [-12264, "SSL_ERROR_BAD_BLOCK_PADDING"],
    [-12263, "SSL_ERROR_RX_RECORD_TOO_LONG"],
    [-12262, "SSL_ERROR_TX_RECORD_TOO_LONG"],
    [-12261, "SSL_ERROR_RX_MALFORMED_HELLO_REQUEST"],
    [-12260, "SSL_ERROR_RX_MALFORMED_CLIENT_HELLO"],
    [-12259, "SSL_ERROR_RX_MALFORMED_SERVER_HELLO"],
    [-12258, "SSL_ERROR_RX_MALFORMED_CERTIFICATE"],
    [-12257, "SSL_ERROR_RX_MALFORMED_SERVER_KEY_EXCH"],
    [-12256, "SSL_ERROR_RX_MALFORMED_CERT_REQUEST"],
    [-12255, "SSL_ERROR_RX_MALFORMED_HELLO_DONE"],
    [-12254, "SSL_ERROR_RX_MALFORMED_CERT_VERIFY"],
    [-12253, "SSL_ERROR_RX_MALFORMED_CLIENT_KEY_EXCH"],
    [-12252, "SSL_ERROR_RX_MALFORMED_FINISHED"],
    [-12251, "SSL_ERROR_RX_MALFORMED_CHANGE_CIPHER"],
    [-12250, "SSL_ERROR_RX_MALFORMED_ALERT"],
    [-12249, "SSL_ERROR_RX_MALFORMED_HANDSHAKE"],
    [-12248, "SSL_ERROR_RX_MALFORMED_APPLICATION_DATA"],
    [-12247, "SSL_ERROR_RX_UNEXPECTED_HELLO_REQUEST"],
    [-12246, "SSL_ERROR_RX_UNEXPECTED_CLIENT_HELLO"],
    [-12245, "SSL_ERROR_RX_UNEXPECTED_SERVER_HELLO"],
    [-12244, "SSL_ERROR_RX_UNEXPECTED_CERTIFICATE"],
    [-12243, "SSL_ERROR_RX_UNEXPECTED_SERVER_KEY_EXCH"],
    [-12242, "SSL_ERROR_RX_UNEXPECTED_CERT_REQUEST"],
    [-12241, "SSL_ERROR_RX_UNEXPECTED_HELLO_DONE"],
    [-12240, "SSL_ERROR_RX_UNEXPECTED_CERT_VERIFY"],
    [-12239, "SSL_ERROR_RX_UNEXPECTED_CLIENT_KEY_EXCH"],
    [-12238, "SSL_ERROR_RX_UNEXPECTED_FINISHED"],
    [-12237, "SSL_ERROR_RX_UNEXPECTED_CHANGE_CIPHER"],
    [-12236, "SSL_ERROR_RX_UNEXPECTED_ALERT"],
    [-12235, "SSL_ERROR_RX_UNEXPECTED_HANDSHAKE"],
    [-12234, "SSL_ERROR_RX_UNEXPECTED_APPLICATION_DATA"],
    [-12233, "SSL_ERROR_RX_UNKNOWN_RECORD_TYPE"],
    [-12232, "SSL_ERROR_RX_UNKNOWN_HANDSHAKE"],
    [-12231, "SSL_ERROR_RX_UNKNOWN_ALERT"],
    [-12230, "SSL_ERROR_CLOSE_NOTIFY_ALERT"],
    [-12229, "SSL_ERROR_HANDSHAKE_UNEXPECTED_ALERT"],
    [-12228, "SSL_ERROR_DECOMPRESSION_FAILURE_ALERT"],
    [-12227, "SSL_ERROR_HANDSHAKE_FAILURE_ALERT"],
    [-12226, "SSL_ERROR_ILLEGAL_PARAMETER_ALERT"],
    [-12225, "SSL_ERROR_UNSUPPORTED_CERT_ALERT"],
    [-12224, "SSL_ERROR_CERTIFICATE_UNKNOWN_ALERT"],
    [-12223, "SSL_ERROR_GENERATE_RANDOM_FAILURE"],
    [-12222, "SSL_ERROR_SIGN_HASHES_FAILURE"],
    [-12221, "SSL_ERROR_EXTRACT_PUBLIC_KEY_FAILURE"],
    [-12220, "SSL_ERROR_SERVER_KEY_EXCHANGE_FAILURE"],
    [-12219, "SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE"],
    [-12218, "SSL_ERROR_ENCRYPTION_FAILURE"],
    [-12217, "SSL_ERROR_DECRYPTION_FAILURE"],
    [-12216, "SSL_ERROR_SOCKET_WRITE_FAILURE"],
    [-12215, "SSL_ERROR_MD5_DIGEST_FAILURE"],
    [-12214, "SSL_ERROR_SHA_DIGEST_FAILURE"],
    [-12213, "SSL_ERROR_MAC_COMPUTATION_FAILURE"],
    [-12212, "SSL_ERROR_SYM_KEY_CONTEXT_FAILURE"],
    [-12211, "SSL_ERROR_SYM_KEY_UNWRAP_FAILURE"],
    [-12210, "SSL_ERROR_PUB_KEY_SIZE_LIMIT_EXCEEDED"],
    [-12209, "SSL_ERROR_IV_PARAM_FAILURE"],
    [-12208, "SSL_ERROR_INIT_CIPHER_SUITE_FAILURE"],
    [-12207, "SSL_ERROR_SESSION_KEY_GEN_FAILURE"],
    [-12206, "SSL_ERROR_NO_SERVER_KEY_FOR_ALG"],
    [-12205, "SSL_ERROR_TOKEN_INSERTION_REMOVAL"],
    [-12204, "SSL_ERROR_TOKEN_SLOT_NOT_FOUND"],
    [-12203, "SSL_ERROR_NO_COMPRESSION_OVERLAP"],
    [-12202, "SSL_ERROR_HANDSHAKE_NOT_COMPLETED"],
    [-12201, "SSL_ERROR_BAD_HANDSHAKE_HASH_VALUE"],
    [-12200, "SSL_ERROR_CERT_KEA_MISMATCH"],
    [-12199, "SSL_ERROR_NO_TRUSTED_SSL_CLIENT_CA"],
    [-12198, "SSL_ERROR_SESSION_NOT_FOUND"],
    [-12197, "SSL_ERROR_DECRYPTION_FAILED_ALERT"],
    [-12196, "SSL_ERROR_RECORD_OVERFLOW_ALERT"],
    [-12195, "SSL_ERROR_UNKNOWN_CA_ALERT"],
    [-12194, "SSL_ERROR_ACCESS_DENIED_ALERT"],
    [-12193, "SSL_ERROR_DECODE_ERROR_ALERT"],
    [-12192, "SSL_ERROR_DECRYPT_ERROR_ALERT"],
    [-12191, "SSL_ERROR_EXPORT_RESTRICTION_ALERT"],
    [-12190, "SSL_ERROR_PROTOCOL_VERSION_ALERT"],
    [-12189, "SSL_ERROR_INSUFFICIENT_SECURITY_ALERT"],
    [-12188, "SSL_ERROR_INTERNAL_ERROR_ALERT"],
    [-12187, "SSL_ERROR_USER_CANCELED_ALERT"],
    [-12186, "SSL_ERROR_NO_RENEGOTIATION_ALERT"],
    [-12185, "SSL_ERROR_SERVER_CACHE_NOT_CONFIGURED"],
    [-12184, "SSL_ERROR_UNSUPPORTED_EXTENSION_ALERT"],
    [-12183, "SSL_ERROR_CERTIFICATE_UNOBTAINABLE_ALERT"],
    [-12182, "SSL_ERROR_UNRECOGNIZED_NAME_ALERT"],
    [-12181, "SSL_ERROR_BAD_CERT_STATUS_RESPONSE_ALERT"],
    [-12180, "SSL_ERROR_BAD_CERT_HASH_VALUE_ALERT"],
    [-12179, "SSL_ERROR_RX_UNEXPECTED_NEW_SESSION_TICKET"],
    [-12178, "SSL_ERROR_RX_MALFORMED_NEW_SESSION_TICKET"],
    [-12177, "SSL_ERROR_DECOMPRESSION_FAILURE"],
    [-12176, "SSL_ERROR_RENEGOTIATION_NOT_ALLOWED"],
    [-12175, "SSL_ERROR_UNSAFE_NEGOTIATION"],
    [-12174, "SSL_ERROR_RX_UNEXPECTED_UNCOMPRESSED_RECORD"],
    [-12173, "SSL_ERROR_WEAK_SERVER_EPHEMERAL_DH_KEY"],
    [-12172, "SSL_ERROR_NEXT_PROTOCOL_DATA_INVALID"],
    [-12171, "SSL_ERROR_FEATURE_NOT_SUPPORTED_FOR_SSL2"],
    [-12170, "SSL_ERROR_FEATURE_NOT_SUPPORTED_FOR_SERVERS"],
    [-12169, "SSL_ERROR_FEATURE_NOT_SUPPORTED_FOR_CLIENTS"],
    [-12168, "SSL_ERROR_INVALID_VERSION_RANGE"],
    [-12167, "SSL_ERROR_CIPHER_DISALLOWED_FOR_VERSION"],
    [-12166, "SSL_ERROR_RX_MALFORMED_HELLO_VERIFY_REQUEST"],
    [-12165, "SSL_ERROR_RX_UNEXPECTED_HELLO_VERIFY_REQUEST"],
    [-12164, "SSL_ERROR_FEATURE_NOT_SUPPORTED_FOR_VERSION"],
    [-12163, "SSL_ERROR_RX_UNEXPECTED_CERT_STATUS"],
    [-12162, "SSL_ERROR_UNSUPPORTED_HASH_ALGORITHM"],
    [-12161, "SSL_ERROR_DIGEST_FAILURE"],
    [-12160, "SSL_ERROR_INCORRECT_SIGNATURE_ALGORITHM"],
    [-12159, "SSL_ERROR_NEXT_PROTOCOL_NO_CALLBACK"],
    [-12158, "SSL_ERROR_NEXT_PROTOCOL_NO_PROTOCOL"],
    [-12157, "SSL_ERROR_INAPPROPRIATE_FALLBACK_ALERT"],
    [-12156, "SSL_ERROR_WEAK_SERVER_CERT_KEY"],
    [-12155, "SSL_ERROR_RX_SHORT_DTLS_READ"],
    [-12154, "SSL_ERROR_NO_SUPPORTED_SIGNATURE_ALGORITHM"],
    [-12153, "SSL_ERROR_UNSUPPORTED_SIGNATURE_ALGORITHM"],
    [-12152, "SSL_ERROR_MISSING_EXTENDED_MASTER_SECRET"],
    [-12151, "SSL_ERROR_UNEXPECTED_EXTENDED_MASTER_SECRET"],
    [-12150, "SSL_ERROR_RX_MALFORMED_KEY_SHARE"],
    [-12149, "SSL_ERROR_MISSING_KEY_SHARE"],
    [-12148, "SSL_ERROR_RX_MALFORMED_ECDHE_KEY_SHARE"],
    [-12147, "SSL_ERROR_RX_MALFORMED_DHE_KEY_SHARE"],
    [-12146, "SSL_ERROR_RX_UNEXPECTED_ENCRYPTED_EXTENSIONS"],
    [-12145, "SSL_ERROR_MISSING_EXTENSION_ALERT"],
    [-12144, "SSL_ERROR_KEY_EXCHANGE_FAILURE"],
    [-12143, "SSL_ERROR_EXTENSION_DISALLOWED_FOR_VERSION"],
    [-12142, "SSL_ERROR_RX_MALFORMED_ENCRYPTED_EXTENSIONS"],
    [-12141, "SSL_ERROR_MALFORMED_PRE_SHARED_KEY"],
    [-12140, "SSL_ERROR_MALFORMED_EARLY_DATA"],
    [-12139, "SSL_ERROR_END_OF_EARLY_DATA_ALERT"],
    [-12138, "SSL_ERROR_MISSING_ALPN_EXTENSION"],
    [-12137, "SSL_ERROR_RX_UNEXPECTED_EXTENSION"],
    [-12136, "SSL_ERROR_MISSING_SUPPORTED_GROUPS_EXTENSION"],
    [-12135, "SSL_ERROR_TOO_MANY_RECORDS"],
    [-12134, "SSL_ERROR_RX_UNEXPECTED_HELLO_RETRY_REQUEST"],
    [-12133, "SSL_ERROR_RX_MALFORMED_HELLO_RETRY_REQUEST"],
    [-12132, "SSL_ERROR_BAD_2ND_CLIENT_HELLO"],
    [-12131, "SSL_ERROR_MISSING_SIGNATURE_ALGORITHMS_EXTENSION"],
    [-12130, "SSL_ERROR_MALFORMED_PSK_KEY_EXCHANGE_MODES"],
    [-12129, "SSL_ERROR_MISSING_PSK_KEY_EXCHANGE_MODES"],
    [-12128, "SSL_ERROR_DOWNGRADE_WITH_EARLY_DATA"],
    [-12127, "SSL_ERROR_TOO_MUCH_EARLY_DATA"],
    [-12126, "SSL_ERROR_RX_UNEXPECTED_END_OF_EARLY_DATA"],
    [-12125, "SSL_ERROR_RX_MALFORMED_END_OF_EARLY_DATA"],
    [-12124, "SSL_ERROR_UNSUPPORTED_EXPERIMENTAL_API"],
    [-12123, "SSL_ERROR_APPLICATION_ABORT"],
    [-12122, "SSL_ERROR_APP_CALLBACK_ERROR"],
    [-12121, "SSL_ERROR_NO_TIMERS_FOUND"],
    [-12120, "SSL_ERROR_MISSING_COOKIE_EXTENSION"],
    [-12119, "SSL_ERROR_RX_UNEXPECTED_KEY_UPDATE"],
    [-12118, "SSL_ERROR_RX_MALFORMED_KEY_UPDATE"],
    [-12117, "SSL_ERROR_TOO_MANY_KEY_UPDATES"],
    [-12116, "SSL_ERROR_HANDSHAKE_FAILED"],
    [-12115, "SSL_ERROR_BAD_RESUMPTION_TOKEN_ERROR"],
    [-12114, "SSL_ERROR_RX_MALFORMED_DTLS_ACK"],
    [-12113, "SSL_ERROR_DH_KEY_TOO_LONG"],
    [-12112, "SSL_ERROR_RX_MALFORMED_ESNI_KEYS"],
    [-12111, "SSL_ERROR_RX_MALFORMED_ESNI_EXTENSION"],
    [-12110, "SSL_ERROR_MISSING_ESNI_EXTENSION"],
    [-12109, "SSL_ERROR_RX_UNEXPECTED_RECORD_TYPE"],
    [-12108, "SSL_ERROR_MISSING_POST_HANDSHAKE_AUTH_EXTENSION"],
    [-12107, "SSL_ERROR_RX_CERTIFICATE_REQUIRED_ALERT"],
    [-12106, "SSL_ERROR_DC_CERT_VERIFY_ALG_MISMATCH"],
    [-12105, "SSL_ERROR_DC_BAD_SIGNATURE"],
    [-12104, "SSL_ERROR_DC_INVALID_KEY_USAGE"],
    [-12103, "SSL_ERROR_DC_EXPIRED"],
    [-12102, "SSL_ERROR_DC_INAPPROPRIATE_VALIDITY_PERIOD"],
    [-12101, "SSL_ERROR_FEATURE_DISABLED"],
    [-12100, "SSL_ERROR_END_OF_LIST"],

    // Copied from mozilla-unified/obj-x86_64-pc-linux-gnu/x86_64-unknown-linux-gnu/release/build/neqo-crypto-ddfa555fd025ac0c/out/nss_secerr.rs
    [-8192, "SEC_ERROR_IO"],
    [-8191, "SEC_ERROR_LIBRARY_FAILURE"],
    [-8190, "SEC_ERROR_BAD_DATA"],
    [-8189, "SEC_ERROR_OUTPUT_LEN"],
    [-8188, "SEC_ERROR_INPUT_LEN"],
    [-8187, "SEC_ERROR_INVALID_ARGS"],
    [-8186, "SEC_ERROR_INVALID_ALGORITHM"],
    [-8185, "SEC_ERROR_INVALID_AVA"],
    [-8184, "SEC_ERROR_INVALID_TIME"],
    [-8183, "SEC_ERROR_BAD_DER"],
    [-8182, "SEC_ERROR_BAD_SIGNATURE"],
    [-8181, "SEC_ERROR_EXPIRED_CERTIFICATE"],
    [-8180, "SEC_ERROR_REVOKED_CERTIFICATE"],
    [-8179, "SEC_ERROR_UNKNOWN_ISSUER"],
    [-8178, "SEC_ERROR_BAD_KEY"],
    [-8177, "SEC_ERROR_BAD_PASSWORD"],
    [-8176, "SEC_ERROR_RETRY_PASSWORD"],
    [-8175, "SEC_ERROR_NO_NODELOCK"],
    [-8174, "SEC_ERROR_BAD_DATABASE"],
    [-8173, "SEC_ERROR_NO_MEMORY"],
    [-8172, "SEC_ERROR_UNTRUSTED_ISSUER"],
    [-8171, "SEC_ERROR_UNTRUSTED_CERT"],
    [-8170, "SEC_ERROR_DUPLICATE_CERT"],
    [-8169, "SEC_ERROR_DUPLICATE_CERT_NAME"],
    [-8168, "SEC_ERROR_ADDING_CERT"],
    [-8167, "SEC_ERROR_FILING_KEY"],
    [-8166, "SEC_ERROR_NO_KEY"],
    [-8165, "SEC_ERROR_CERT_VALID"],
    [-8164, "SEC_ERROR_CERT_NOT_VALID"],
    [-8163, "SEC_ERROR_CERT_NO_RESPONSE"],
    [-8162, "SEC_ERROR_EXPIRED_ISSUER_CERTIFICATE"],
    [-8161, "SEC_ERROR_CRL_EXPIRED"],
    [-8160, "SEC_ERROR_CRL_BAD_SIGNATURE"],
    [-8159, "SEC_ERROR_CRL_INVALID"],
    [-8158, "SEC_ERROR_EXTENSION_VALUE_INVALID"],
    [-8157, "SEC_ERROR_EXTENSION_NOT_FOUND"],
    [-8156, "SEC_ERROR_CA_CERT_INVALID"],
    [-8155, "SEC_ERROR_PATH_LEN_CONSTRAINT_INVALID"],
    [-8154, "SEC_ERROR_CERT_USAGES_INVALID"],
    [-8153, "SEC_INTERNAL_ONLY"],
    [-8152, "SEC_ERROR_INVALID_KEY"],
    [-8151, "SEC_ERROR_UNKNOWN_CRITICAL_EXTENSION"],
    [-8150, "SEC_ERROR_OLD_CRL"],
    [-8149, "SEC_ERROR_NO_EMAIL_CERT"],
    [-8148, "SEC_ERROR_NO_RECIPIENT_CERTS_QUERY"],
    [-8147, "SEC_ERROR_NOT_A_RECIPIENT"],
    [-8146, "SEC_ERROR_PKCS7_KEYALG_MISMATCH"],
    [-8145, "SEC_ERROR_PKCS7_BAD_SIGNATURE"],
    [-8144, "SEC_ERROR_UNSUPPORTED_KEYALG"],
    [-8143, "SEC_ERROR_DECRYPTION_DISALLOWED"],
    [-8142, "XP_SEC_FORTEZZA_BAD_CARD"],
    [-8141, "XP_SEC_FORTEZZA_NO_CARD"],
    [-8140, "XP_SEC_FORTEZZA_NONE_SELECTED"],
    [-8139, "XP_SEC_FORTEZZA_MORE_INFO"],
    [-8138, "XP_SEC_FORTEZZA_PERSON_NOT_FOUND"],
    [-8137, "XP_SEC_FORTEZZA_NO_MORE_INFO"],
    [-8136, "XP_SEC_FORTEZZA_BAD_PIN"],
    [-8135, "XP_SEC_FORTEZZA_PERSON_ERROR"],
    [-8134, "SEC_ERROR_NO_KRL"],
    [-8133, "SEC_ERROR_KRL_EXPIRED"],
    [-8132, "SEC_ERROR_KRL_BAD_SIGNATURE"],
    [-8131, "SEC_ERROR_REVOKED_KEY"],
    [-8130, "SEC_ERROR_KRL_INVALID"],
    [-8129, "SEC_ERROR_NEED_RANDOM"],
    [-8128, "SEC_ERROR_NO_MODULE"],
    [-8127, "SEC_ERROR_NO_TOKEN"],
    [-8126, "SEC_ERROR_READ_ONLY"],
    [-8125, "SEC_ERROR_NO_SLOT_SELECTED"],
    [-8124, "SEC_ERROR_CERT_NICKNAME_COLLISION"],
    [-8123, "SEC_ERROR_KEY_NICKNAME_COLLISION"],
    [-8122, "SEC_ERROR_SAFE_NOT_CREATED"],
    [-8121, "SEC_ERROR_BAGGAGE_NOT_CREATED"],
    [-8120, "XP_JAVA_REMOVE_PRINCIPAL_ERROR"],
    [-8119, "XP_JAVA_DELETE_PRIVILEGE_ERROR"],
    [-8118, "XP_JAVA_CERT_NOT_EXISTS_ERROR"],
    [-8117, "SEC_ERROR_BAD_EXPORT_ALGORITHM"],
    [-8116, "SEC_ERROR_EXPORTING_CERTIFICATES"],
    [-8115, "SEC_ERROR_IMPORTING_CERTIFICATES"],
    [-8114, "SEC_ERROR_PKCS12_DECODING_PFX"],
    [-8113, "SEC_ERROR_PKCS12_INVALID_MAC"],
    [-8112, "SEC_ERROR_PKCS12_UNSUPPORTED_MAC_ALGORITHM"],
    [-8111, "SEC_ERROR_PKCS12_UNSUPPORTED_TRANSPORT_MODE"],
    [-8110, "SEC_ERROR_PKCS12_CORRUPT_PFX_STRUCTURE"],
    [-8109, "SEC_ERROR_PKCS12_UNSUPPORTED_PBE_ALGORITHM"],
    [-8108, "SEC_ERROR_PKCS12_UNSUPPORTED_VERSION"],
    [-8107, "SEC_ERROR_PKCS12_PRIVACY_PASSWORD_INCORRECT"],
    [-8106, "SEC_ERROR_PKCS12_CERT_COLLISION"],
    [-8105, "SEC_ERROR_USER_CANCELLED"],
    [-8104, "SEC_ERROR_PKCS12_DUPLICATE_DATA"],
    [-8103, "SEC_ERROR_MESSAGE_SEND_ABORTED"],
    [-8102, "SEC_ERROR_INADEQUATE_KEY_USAGE"],
    [-8101, "SEC_ERROR_INADEQUATE_CERT_TYPE"],
    [-8100, "SEC_ERROR_CERT_ADDR_MISMATCH"],
    [-8099, "SEC_ERROR_PKCS12_UNABLE_TO_IMPORT_KEY"],
    [-8098, "SEC_ERROR_PKCS12_IMPORTING_CERT_CHAIN"],
    [-8097, "SEC_ERROR_PKCS12_UNABLE_TO_LOCATE_OBJECT_BY_NAME"],
    [-8096, "SEC_ERROR_PKCS12_UNABLE_TO_EXPORT_KEY"],
    [-8095, "SEC_ERROR_PKCS12_UNABLE_TO_WRITE"],
    [-8094, "SEC_ERROR_PKCS12_UNABLE_TO_READ"],
    [-8093, "SEC_ERROR_PKCS12_KEY_DATABASE_NOT_INITIALIZED"],
    [-8092, "SEC_ERROR_KEYGEN_FAIL"],
    [-8091, "SEC_ERROR_INVALID_PASSWORD"],
    [-8090, "SEC_ERROR_RETRY_OLD_PASSWORD"],
    [-8089, "SEC_ERROR_BAD_NICKNAME"],
    [-8088, "SEC_ERROR_NOT_FORTEZZA_ISSUER"],
    [-8087, "SEC_ERROR_CANNOT_MOVE_SENSITIVE_KEY"],
    [-8086, "SEC_ERROR_JS_INVALID_MODULE_NAME"],
    [-8085, "SEC_ERROR_JS_INVALID_DLL"],
    [-8084, "SEC_ERROR_JS_ADD_MOD_FAILURE"],
    [-8083, "SEC_ERROR_JS_DEL_MOD_FAILURE"],
    [-8082, "SEC_ERROR_OLD_KRL"],
    [-8081, "SEC_ERROR_CKL_CONFLICT"],
    [-8080, "SEC_ERROR_CERT_NOT_IN_NAME_SPACE"],
    [-8079, "SEC_ERROR_KRL_NOT_YET_VALID"],
    [-8078, "SEC_ERROR_CRL_NOT_YET_VALID"],
    [-8077, "SEC_ERROR_UNKNOWN_CERT"],
    [-8076, "SEC_ERROR_UNKNOWN_SIGNER"],
    [-8075, "SEC_ERROR_CERT_BAD_ACCESS_LOCATION"],
    [-8074, "SEC_ERROR_OCSP_UNKNOWN_RESPONSE_TYPE"],
    [-8073, "SEC_ERROR_OCSP_BAD_HTTP_RESPONSE"],
    [-8072, "SEC_ERROR_OCSP_MALFORMED_REQUEST"],
    [-8071, "SEC_ERROR_OCSP_SERVER_ERROR"],
    [-8070, "SEC_ERROR_OCSP_TRY_SERVER_LATER"],
    [-8069, "SEC_ERROR_OCSP_REQUEST_NEEDS_SIG"],
    [-8068, "SEC_ERROR_OCSP_UNAUTHORIZED_REQUEST"],
    [-8067, "SEC_ERROR_OCSP_UNKNOWN_RESPONSE_STATUS"],
    [-8066, "SEC_ERROR_OCSP_UNKNOWN_CERT"],
    [-8065, "SEC_ERROR_OCSP_NOT_ENABLED"],
    [-8064, "SEC_ERROR_OCSP_NO_DEFAULT_RESPONDER"],
    [-8063, "SEC_ERROR_OCSP_MALFORMED_RESPONSE"],
    [-8062, "SEC_ERROR_OCSP_UNAUTHORIZED_RESPONSE"],
    [-8061, "SEC_ERROR_OCSP_FUTURE_RESPONSE"],
    [-8060, "SEC_ERROR_OCSP_OLD_RESPONSE"],
    [-8059, "SEC_ERROR_DIGEST_NOT_FOUND"],
    [-8058, "SEC_ERROR_UNSUPPORTED_MESSAGE_TYPE"],
    [-8057, "SEC_ERROR_MODULE_STUCK"],
    [-8056, "SEC_ERROR_BAD_TEMPLATE"],
    [-8055, "SEC_ERROR_CRL_NOT_FOUND"],
    [-8054, "SEC_ERROR_REUSED_ISSUER_AND_SERIAL"],
    [-8053, "SEC_ERROR_BUSY"],
    [-8052, "SEC_ERROR_EXTRA_INPUT"],
    [-8051, "SEC_ERROR_UNSUPPORTED_ELLIPTIC_CURVE"],
    [-8050, "SEC_ERROR_UNSUPPORTED_EC_POINT_FORM"],
    [-8049, "SEC_ERROR_UNRECOGNIZED_OID"],
    [-8048, "SEC_ERROR_OCSP_INVALID_SIGNING_CERT"],
    [-8047, "SEC_ERROR_REVOKED_CERTIFICATE_CRL"],
    [-8046, "SEC_ERROR_REVOKED_CERTIFICATE_OCSP"],
    [-8045, "SEC_ERROR_CRL_INVALID_VERSION"],
    [-8044, "SEC_ERROR_CRL_V1_CRITICAL_EXTENSION"],
    [-8043, "SEC_ERROR_CRL_UNKNOWN_CRITICAL_EXTENSION"],
    [-8042, "SEC_ERROR_UNKNOWN_OBJECT_TYPE"],
    [-8041, "SEC_ERROR_INCOMPATIBLE_PKCS11"],
    [-8040, "SEC_ERROR_NO_EVENT"],
    [-8039, "SEC_ERROR_CRL_ALREADY_EXISTS"],
    [-8038, "SEC_ERROR_NOT_INITIALIZED"],
    [-8037, "SEC_ERROR_TOKEN_NOT_LOGGED_IN"],
    [-8036, "SEC_ERROR_OCSP_RESPONDER_CERT_INVALID"],
    [-8035, "SEC_ERROR_OCSP_BAD_SIGNATURE"],
    [-8034, "SEC_ERROR_OUT_OF_SEARCH_LIMITS"],
    [-8033, "SEC_ERROR_INVALID_POLICY_MAPPING"],
    [-8032, "SEC_ERROR_POLICY_VALIDATION_FAILED"],
    [-8031, "SEC_ERROR_UNKNOWN_AIA_LOCATION_TYPE"],
    [-8030, "SEC_ERROR_BAD_HTTP_RESPONSE"],
    [-8029, "SEC_ERROR_BAD_LDAP_RESPONSE"],
    [-8028, "SEC_ERROR_FAILED_TO_ENCODE_DATA"],
    [-8027, "SEC_ERROR_BAD_INFO_ACCESS_LOCATION"],
    [-8026, "SEC_ERROR_LIBPKIX_INTERNAL"],
    [-8025, "SEC_ERROR_PKCS11_GENERAL_ERROR"],
    [-8024, "SEC_ERROR_PKCS11_FUNCTION_FAILED"],
    [-8023, "SEC_ERROR_PKCS11_DEVICE_ERROR"],
    [-8022, "SEC_ERROR_BAD_INFO_ACCESS_METHOD"],
    [-8021, "SEC_ERROR_CRL_IMPORT_FAILED"],
    [-8020, "SEC_ERROR_EXPIRED_PASSWORD"],
    [-8019, "SEC_ERROR_LOCKED_PASSWORD"],
    [-8018, "SEC_ERROR_UNKNOWN_PKCS11_ERROR"],
    [-8017, "SEC_ERROR_BAD_CRL_DP_URL"],
    [-8016, "SEC_ERROR_CERT_SIGNATURE_ALGORITHM_DISABLED"],
    [-8015, "SEC_ERROR_LEGACY_DATABASE"],
    [-8014, "SEC_ERROR_APPLICATION_CALLBACK_ERROR"],
    [-8013, "SEC_ERROR_END_OF_LIST"],

    // Copied from mozilla-unified/obj-x86_64-pc-linux-gnu/x86_64-unknown-linux-gnu/release/build/neqo-crypto-ddfa555fd025ac0c/out/mozpkix.rs
    [-16384, "MOZILLA_PKIX_ERROR_KEY_PINNING_FAILURE"],
    [-16383, "MOZILLA_PKIX_ERROR_CA_CERT_USED_AS_END_ENTITY"],
    [-16382, "MOZILLA_PKIX_ERROR_INADEQUATE_KEY_SIZE"],
    [-16381, "MOZILLA_PKIX_ERROR_V1_CERT_USED_AS_CA"],
    [-16380, "MOZILLA_PKIX_ERROR_NO_RFC822NAME_MATCH"],
    [-16379, "MOZILLA_PKIX_ERROR_NOT_YET_VALID_CERTIFICATE"],
    [-16378, "MOZILLA_PKIX_ERROR_NOT_YET_VALID_ISSUER_CERTIFICATE"],
    [-16377, "MOZILLA_PKIX_ERROR_SIGNATURE_ALGORITHM_MISMATCH"],
    [-16376, "MOZILLA_PKIX_ERROR_OCSP_RESPONSE_FOR_CERT_MISSING"],
    [-16375, "MOZILLA_PKIX_ERROR_VALIDITY_TOO_LONG"],
    [-16374, "MOZILLA_PKIX_ERROR_REQUIRED_TLS_FEATURE_MISSING"],
    [-16373, "MOZILLA_PKIX_ERROR_INVALID_INTEGER_ENCODING"],
    [-16372, "MOZILLA_PKIX_ERROR_EMPTY_ISSUER_NAME"],
    [-16371, "MOZILLA_PKIX_ERROR_ADDITIONAL_POLICY_CONSTRAINT_FAILED"],
    [-16370, "MOZILLA_PKIX_ERROR_SELF_SIGNED_CERT"],
    [-16369, "MOZILLA_PKIX_ERROR_MITM_DETECTED"],
]);

function pathToFile(path) {
    return new FileUtils.File(path);
}

function readFile(file) {
    let fstream = Cc["@mozilla.org/network/file-input-stream;1"]
        .createInstance(Ci.nsIFileInputStream);
    fstream.init(file, -1, 0, 0);
    let data = fstream.available() > 0 ? NetUtil.readInputStreamToString(fstream, fstream.available()) : "";
    fstream.close();
    return data;
}

function loadPEM(path) {
    let pem = readFile(pathToFile(path));
    
    const header = /-----BEGIN CERTIFICATE-----/;
    const footer = /-----END CERTIFICATE-----/;
    let lines = pem.split(/[\r\n]/);
    let certs = [];
    let currentCert = "";
    let addingCert = false;
    for (let line of lines) {
        if (line.match(header)) {
            addingCert = true;
            continue;
        }
        if (line.match(footer)) {
            addingCert = false;
            certs.push(currentCert);
            currentCert = "";
            continue;
        }
        if (addingCert) {
            currentCert += line;
        }
    }

    return certs;
}

function loadCerts(certsPath) {
    let certdb = Cc["@mozilla.org/security/x509certdb;1"]
        .getService(Ci.nsIX509CertDB);
    let pemCerts = loadPEM(certsPath);
    let certs = [];
    for (let pemCert of pemCerts) {
        try {
            let cert = certdb.constructX509FromBase64(pemCert);
            certs.push(cert);
        } catch (e) {
            dump("couldn't construct certificate: " + e + "\n");
        }
    }
    return certs;
}

function errorCodeToName(code) {
    if (code == 0) {
        return "OK";
    }
    return ERROR_CODES.get(code) || code;
}

class VerifyResult {
    constructor(resolve) {
        this.resolve = resolve;
    }

    verifyCertFinished(aPRErrorCode) {
        this.resolve(aPRErrorCode);
    }
}

function spinMainThreadUntil(predicate) {
    let threadManager = Cc["@mozilla.org/thread-manager;1"]
        .getService(Ci.nsIThreadManager);
    let mainThread = threadManager.currentThread;

    while (!predicate()) {
        mainThread.processNextEvent(true);
    }
}

async function main(args) {
    if (args.length != 2) {
        throw "Usage: verify.js <roots.pem> <time>";
    }

    let roots_path = args[0];
    let timestamp = parseInt(args[1]);

    let certdb = Cc["@mozilla.org/security/x509certdb;1"]
        .getService(Ci.nsIX509CertDB);

    let roots = loadCerts(roots_path);
    // NOTE: we assume that all built-in roots have been removed
    // see security/nss/lib/ckfw/builtins/certdata.txt
    for (const root of roots) {
        certdb.setCertTrustFromString(root, "Cu,Cu,Cu");
    }

    const leaf_prefix = "leaf: ";
    const interm_prefix = "interm: ";
    const domain_prefix = "domain: ";
    const repeat_prefix = "repeat: ";

    let repeat_count = 1;

    let leaf_base64 = null;
    let interm_base64 = [];

    // There is an annoying issue in xpcshell
    // where `readline` only reads the first 4096
    // characters off a line, so we have to keep
    // track of unfinished lines
    let last_reading = 0; // 1 for leaf; 2 for interm
    let read_sofar = "";

    // Three types of input lines:
    // 1. "leaf: <base64>": set leaf cert
    // 2. "interm: <base64>": add an intermediate cert
    // 3. "domain: <domain>": validate the domain based on previous certs
    // 4. "repeat: <n>": set repeat to n
    //
    // The input is expected to be in the format of (12*3)*
    while (true) {
        let line = readline();

        if (line.startsWith(leaf_prefix)) {
            line = line.slice(leaf_prefix.length);

            if (leaf_base64) {
                print("error: leaf already set");
                return 1;
            }

            if (last_reading != 0) {
                print("error: ill-formed input");
                return 1;
            }

            last_reading = 1
            read_sofar = line
        } else if (line.startsWith(interm_prefix)) {
            line = line.slice(interm_prefix.length);

            if (last_reading == 1) {
                leaf_base64 = read_sofar;
                last_reading = 0;
            } else if (last_reading == 2) {
                interm_base64.push(read_sofar);
                last_reading = 0;
            }

            if (!leaf_base64) {
                print("error: leaf not set");
                return 1;
            }

            last_reading = 2
            read_sofar = line
        } else if (line.startsWith(domain_prefix)) {
            line = line.slice(domain_prefix.length);
            hostname = line;

            if (last_reading == 1) {
                leaf_base64 = read_sofar;
                last_reading = 0;
            } else if (last_reading == 2) {
                interm_base64.push(read_sofar);
                last_reading = 0;
            }

            if (!leaf_base64) {
                print("error: leaf not set");
                return 1;
            }

            let result;

            result = certdb.benchVerifyCertAtTime(
                leaf_base64,
                interm_base64,
                certificateUsageSSLServer,
                Ci.nsIX509CertDB.FLAG_LOCAL_ONLY,
                hostname,
                timestamp,
                repeat_count,
            );

            err_code = result[0];
            durations = result.slice(1);

            dump(`result: ${errorCodeToName(err_code)}`);
            for (const duration of durations) {
                dump(` ${duration}`)
            }
            dump("\n")

            leaf_base64 = null;
            interm = [];
        } else if (line.startsWith(repeat_prefix)) {
            line = line.slice(repeat_prefix.length);
            repeat_count = parseInt(line);

            if (last_reading == 1) {
                leaf_base64 = read_sofar;
                last_reading = 0;
            } else if (last_reading == 2) {
                interm_base64.push(read_sofar);
                last_reading = 0;
            }

            if (repeat_count <= 0) {
                print("error: invalid repeat");
                return 1;
            }
        } else {
            read_sofar += line;
        }
    }

    return 0;
}

let done = false;
main(arguments).finally(() => { done = true; })
spinMainThreadUntil(() => done);
