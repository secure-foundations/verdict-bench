#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/x509.h"
#include "openssl/x509_vfy.h"
#include "openssl/x509v3.h"

#define MAX_REPEAT 128
#define MAX_CHAIN_SIZE 64

// If `str` has prefix `prefix`, return the remaining string
// Otherwise return NULL
char *check_prefix(char *str, const char *prefix) {
    size_t prefix_len = strlen(prefix);

    if (strncmp(str, prefix, prefix_len) == 0) {
        return str + prefix_len;
    }

    return NULL;
}

// Parse base64 + DER encoded X.509
X509 *parse_x509(const char *base64) {
    BIO *bio = BIO_new_mem_buf(base64, -1);
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);

    // Same size as the base64 encoding is enough for decoding
    size_t buffer_size = strlen(base64) + 1;
    char *der = malloc(buffer_size);
    int len = BIO_read(bio, der, buffer_size);
    if (len <= 0) {
        free(der);
        BIO_free_all(bio);
        return NULL;
    }

    // Parse DER to X509
    const unsigned char *p = (unsigned char*) der;
    X509 *cert = d2i_X509(NULL, &p, len);

    free(der);
    BIO_free_all(bio);

    return cert;
}

// Replace all c1 to c2 in a string
void replace_str(char *str, char c1, char c2) {
    while (*str != '\0') {
        if (*str == c1) {
            *str = c2;
        }
        str++;
    }
}

// Parse and validate a given chain in base64
// Returns 1 on success, otherwise *err is set to the error message from OpenSSL
int x509_validte(X509_STORE *roots, int64_t timestamp, char **cert_base64, size_t num_certs, const char *hostname, char **err) {
    X509_VERIFY_PARAM *param = NULL;
    X509_STORE_CTX *ctx = NULL;
    X509 *leaf = NULL;

    int res = 0;
    *err = NULL;

    // Parse the chain of certificates read so far
    STACK_OF(X509) *chain = sk_X509_new_null();
    for (size_t i = 0; i < num_certs; i++) {
        if (!cert_base64[i]) {
            printf("error: allocation error\n");
            exit(1);
        }

        X509 *cert = parse_x509(cert_base64[i]);
        if (!cert) {
            *err = strdup("parse_error");
            goto END_VALIDATION;
        }
        sk_X509_push(chain, cert);
    }

    // Initialize validation context
    ctx = X509_STORE_CTX_new();
    if (!ctx) {
        printf("error: failed to create X509_STORE_CTX\n");
        exit(1);
    }

    // Set validation params
    param = X509_VERIFY_PARAM_new();
    if (!param) {
        printf("error: failed to initialize parameters\n");
        exit(1);
    }

    X509_VERIFY_PARAM_set_time(param, timestamp);
    X509_VERIFY_PARAM_set_purpose(param, X509_PURPOSE_SSL_SERVER);
    X509_VERIFY_PARAM_set_depth(param, MAX_CHAIN_SIZE);
    X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_X509_STRICT);
    // Align the flags with x509-limbo: https://github.com/C2SP/x509-limbo/blob/main/harness/openssl/main.cpp#L131C37-L131C62
    // which is needed for some test cases
    X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_PARTIAL_CHAIN);
    if (hostname) {
        X509_VERIFY_PARAM_set1_host(param, hostname, 0);
    }
    X509_STORE_set1_param(roots, param);

    // Set chain in the context
    leaf = sk_X509_value(chain, 0);
    sk_X509_shift(chain);
    if (!X509_STORE_CTX_init(ctx, roots, leaf, chain)) {
        printf("error: failed to initialize X509_STORE_CTX\n");
        exit(1);
    }

    res = X509_verify_cert(ctx);

    int error = X509_STORE_CTX_get_error(ctx);
    if (res <= 0 || error != X509_V_OK) {
        *err = strdup(X509_verify_cert_error_string(error));
        replace_str(*err, ' ', '_');
        res = 0;
    }

    // Clean up
END_VALIDATION:
    sk_X509_pop_free(chain, X509_free);

    if (param) X509_VERIFY_PARAM_free(param);
    if (ctx) X509_STORE_CTX_free(ctx);
    if (leaf) X509_free(leaf);

    return res;
}

int main(int argc, char *argv[]) {
    // fprintf(stderr, "version: %lx\n", OPENSSL_VERSION_NUMBER);

    if (argc != 3) {
        fprintf(stderr, "usage: %s <roots.pem> <timestamp>\n", argv[0]);
        return 1;
    }

    const char *roots_path = argv[1];
    int64_t timestamp = strtol(argv[2], NULL, 10);

    if (timestamp == 0) {
        fprintf(stderr, "failed to parse input timestamp\n");
        return 1;
    }

    // Load root certificates
    X509_STORE *roots = X509_STORE_new();
    if (!roots) {
        fprintf(stderr, "failed to create root store\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if (!X509_STORE_load_locations(roots, roots_path, NULL)) {
        fprintf(stderr, "failed to load roots file: %s\n", roots_path);
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // X509_STORE_set_verify_cb(roots, cb);

    char *line = NULL;
    size_t len = 0;

    uint64_t measurements[MAX_REPEAT];

    char *cert_base64[MAX_CHAIN_SIZE];
    size_t cur_num_certs = 0;

    size_t repeat = 1;
    size_t n_read;

    // Main benchmarking loop
    while ((n_read = getline(&line, &len, stdin)) != -1) {
        char *rem = NULL;

        // Remove newline at the end
        if (n_read > 0 && line[n_read - 1] == '\n') {
            line[n_read - 1] = '\0';
        }

        if (rem = check_prefix(line, "leaf: ")) {
            if (cur_num_certs != 0) {
                printf("error: leaf read multiple times\n");
                exit(1);
            }

            cert_base64[cur_num_certs++] = strdup(rem);
        } else if (rem = check_prefix(line, "interm: ")) {
            if (cur_num_certs == 0) {
                printf("error: leaf not read yet\n");
                exit(1);
            }

            cert_base64[cur_num_certs++] = strdup(rem);
        } else if (rem = check_prefix(line, "repeat: ")) {
            int64_t num = strtol(rem, NULL, 10);

            if (num <= 0 || num > MAX_REPEAT) {
                printf("error: invalid repeat\n");
                exit(1);
            }

            repeat = num;
        } else {
            char *hostname = NULL;

            if (rem = check_prefix(line, "validate")) {
            } else if (rem = check_prefix(line, "domain: ")) {
                hostname = rem;
            } else {
                printf("error: invalid command: %s", line);
                exit(1);
            }

            if (cur_num_certs == 0) {
                printf("error: leaf not read yet\n");
                exit(1);
            }

            char *err = NULL;
            int res = 0;

            struct timespec start, end;

            for (size_t i = 0; i < repeat; i++) {
                // Free the previous error message
                free(err);

                if (clock_gettime(CLOCK_REALTIME, &start) == -1) {
                    printf("error: failed to get wall-clock time\n");
                    exit(1);
                }

                res = x509_validte(roots, timestamp, cert_base64, cur_num_certs, hostname, &err);

                if (clock_gettime(CLOCK_REALTIME, &end) == -1) {
                    printf("error: failed to get wall-clock time\n");
                    exit(1);
                }

                measurements[i] =
                    (end.tv_sec * 1000000ULL + end.tv_nsec / 1000) -
                    (start.tv_sec * 1000000ULL + start.tv_nsec / 1000);
            }

            if (res == 1) {
                printf("result: OK");
            } else if (err) {
                printf("result: %s", err);
            } else {
                printf("result: no_error_msg");
            }

            for (size_t i = 0; i < repeat; i++) {
                printf(" %ld", measurements[i]);
            }
            printf("\n");

            // Clean up
            free(err);
            for (size_t i = 0; i < cur_num_certs; i++) {
                free(cert_base64[i]);
            }
            cur_num_certs = 0;

            fflush(stdout);
        }
    }

    free(line);
    X509_STORE_free(roots);
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}
