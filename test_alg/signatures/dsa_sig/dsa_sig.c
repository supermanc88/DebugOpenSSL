#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/dsa.h>
#include <openssl/x509.h>
#include <openssl/bn.h>


int call_dsa_gen_p_q_g(unsigned char **p, int *p_len,
                       unsigned char **q, int *q_len,
                       unsigned char **g, int *g_len)
{
    int ret = -1;
    DSA *dsa = NULL;
    const BIGNUM *dsa_p = NULL, *dsa_q = NULL, *dsa_g = NULL;

    if (!p || !p_len || !q || !q_len || !g || !g_len) {
        fprintf(stderr, "Invalid input parameter\n");
        goto out;
    }

    dsa = DSA_new();
    if (!dsa) {
        fprintf(stderr, "DSA_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto out;
    }

    if (DSA_generate_parameters_ex(dsa, 1024, NULL, 0, NULL, NULL, NULL) != 1) {
        fprintf(stderr, "DSA_generate_parameters_ex failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto out;
    }

    DSA_get0_pqg(dsa, &dsa_p, &dsa_q, &dsa_g);
    if (!dsa_p || !dsa_q || !dsa_g) {
        fprintf(stderr, "DSA_get0_pqg failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto out;
    }

    *p_len = BN_num_bytes(dsa_p);
    *q_len = BN_num_bytes(dsa_q);
    *g_len = BN_num_bytes(dsa_g);

    *p = (unsigned char *)malloc(*p_len);
    *q = (unsigned char *)malloc(*q_len);
    *g = (unsigned char *)malloc(*g_len);
    if (!*p || !*q || !*g) {
        fprintf(stderr, "Memory allocation failed\n");
        goto out;
    }

    BN_bn2bin(dsa_p, *p);
    BN_bn2bin(dsa_q, *q);
    BN_bn2bin(dsa_g, *g);

    ret = 0;
out:
    if (ret != 0) {
        if (p && *p) {
            free(*p);
            *p = NULL;
        }
        if (q && *q) {
            free(*q);
            *q = NULL;
        }
        if (g && *g) {
            free(*g);
            *g = NULL;
        }
    }
    if (dsa) {
        DSA_free(dsa);
    }
    return ret;
}

int call_dsa_gen_key(unsigned char *p, int p_len,
                     unsigned char *q, int q_len,
                     unsigned char *g, int g_len,
                     unsigned char **pub_key, int *pub_key_len,
                     unsigned char **priv_key, int *priv_key_len) {
    int ret = 0;
    DSA *dsa = NULL;
    const BIGNUM *dsa_pub_key = NULL, *dsa_priv_key = NULL;
    BIGNUM *dsa_p = NULL, *dsa_q = NULL, *dsa_g = NULL;

    if (!p || !q || !g || !pub_key || !pub_key_len || !priv_key || !priv_key_len) {
        fprintf(stderr, "Invalid input parameter\n");
        ret = -1;
        goto out;
    }

    dsa = DSA_new();
    if (!dsa) {
        fprintf(stderr, "DSA_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    dsa_p = BN_bin2bn(p, p_len, NULL);
    dsa_q = BN_bin2bn(q, q_len, NULL);
    dsa_g = BN_bin2bn(g, g_len, NULL);
    if (!dsa_p || !dsa_q || !dsa_g) {
        fprintf(stderr, "BN_bin2bn failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    if (DSA_set0_pqg(dsa, dsa_p, dsa_q, dsa_g) != 1) {
        fprintf(stderr, "DSA_set0_pqg failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    /* After successful DSA_set0_pqg, the BIGNUM pointers are owned by DSA object */
    dsa_p = dsa_q = dsa_g = NULL;

    if (DSA_generate_key(dsa) != 1) {
        fprintf(stderr, "DSA_generate_key failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    DSA_get0_key(dsa, &dsa_pub_key, &dsa_priv_key);
    if (!dsa_pub_key || !dsa_priv_key) {
        fprintf(stderr, "DSA_get0_key failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    *pub_key_len = BN_num_bytes(dsa_pub_key);
    *priv_key_len = BN_num_bytes(dsa_priv_key);

    *pub_key = (unsigned char *)malloc(*pub_key_len);
    *priv_key = (unsigned char *)malloc(*priv_key_len);
    if (!*pub_key || !*priv_key) {
        fprintf(stderr, "Memory allocation failed\n");
        ret = -1;
        goto out;
    }

    BN_bn2bin(dsa_pub_key, *pub_key);
    BN_bn2bin(dsa_priv_key, *priv_key);

out:
    if (ret != 0) {
        if (pub_key && *pub_key) {
            free(*pub_key);
            *pub_key = NULL;
        }
        if (priv_key && *priv_key) {
            free(*priv_key);
            *priv_key = NULL;
        }
        /* Free BIGNUMs only if DSA_set0_pqg failed */
        if (dsa_p) BN_free(dsa_p);
        if (dsa_q) BN_free(dsa_q);
        if (dsa_g) BN_free(dsa_g);
    }
    if (dsa) {
        DSA_free(dsa);
    }
    return ret;
}

int call_dsa_sign(unsigned char *p, int p_len,
                  unsigned char *q, int q_len,
                  unsigned char *g, int g_len,
                  unsigned char *priv_key, int priv_key_len,
                  unsigned char *data, int data_len,
                  unsigned char **sig, int *sig_len) {
    int ret = 0;
    DSA *dsa = NULL;
    BIGNUM *dsa_priv_key = NULL;
    BIGNUM *dsa_p = NULL, *dsa_q = NULL, *dsa_g = NULL;
    unsigned int sig_size = 0;
    unsigned char *signature = NULL;

    if (!p || !q || !g || !priv_key || !data || !sig || !sig_len) {
        fprintf(stderr, "Invalid input parameter\n");
        ret = -1;
        goto out;
    }

    dsa = DSA_new();
    if (!dsa) {
        fprintf(stderr, "DSA_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    dsa_p = BN_bin2bn(p, p_len, NULL);
    dsa_q = BN_bin2bn(q, q_len, NULL);
    dsa_g = BN_bin2bn(g, g_len, NULL);
    if (!dsa_p || !dsa_q || !dsa_g) {
        fprintf(stderr, "BN_bin2bn failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    if (DSA_set0_pqg(dsa, dsa_p, dsa_q, dsa_g) != 1) {
        fprintf(stderr, "DSA_set0_pqg failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    /* After successful DSA_set0_pqg, the BIGNUM pointers are owned by DSA object */
    dsa_p = dsa_q = dsa_g = NULL;

    dsa_priv_key = BN_bin2bn(priv_key, priv_key_len, NULL);
    if (!dsa_priv_key) {
        fprintf(stderr, "BN_bin2bn for priv_key failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    if (DSA_set0_key(dsa, NULL, dsa_priv_key) != 1) {
        fprintf(stderr, "DSA_set0_key failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }
    /* After successful DSA_set0_key, the BIGNUM pointer is owned by DSA object */
    dsa_priv_key = NULL;

    sig_size = DSA_size(dsa);
    signature = (unsigned char *)malloc(sig_size);
    if (!signature) {
        fprintf(stderr, "Memory allocation failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    if (DSA_sign(0, data, data_len, signature, &sig_size, dsa) != 1) {
        fprintf(stderr, "DSA_sign failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ret = -1;
        goto out;
    }

    *sig = signature;
    *sig_len = sig_size;
    ret = 0;
    signature = NULL; // ownership transferred

out:
    if (dsa) {
        DSA_free(dsa);
    }
    if (ret != 0) {
        if (sig && *sig) {
            free(*sig);
            *sig = NULL;
        }
        if (dsa_p) BN_free(dsa_p);
        if (dsa_q) BN_free(dsa_q);
        if (dsa_g) BN_free(dsa_g);
        if (dsa_priv_key) BN_free(dsa_priv_key);
    }
    return ret;
}

int call_dsa_verify(unsigned char *p, int p_len,
                    unsigned char *q, int q_len,
                    unsigned char *g, int g_len,
                    unsigned char *pub_key, int pub_key_len,
                    unsigned char *data, int data_len,
                    unsigned char *sig, int sig_len) {
    int ret = -1;
    DSA *dsa = NULL;
    BIGNUM *dsa_pub_key = NULL;
    BIGNUM *dsa_p = NULL, *dsa_q = NULL, *dsa_g = NULL;
    int verify_status = 0;

    if (!p || !q || !g || !pub_key || !data || !sig) {
        fprintf(stderr, "Invalid input parameter\n");
        goto out;
    }

    dsa = DSA_new();
    if (!dsa) {
        fprintf(stderr, "DSA_new failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto out;
    }

    dsa_p = BN_bin2bn(p, p_len, NULL);
    dsa_q = BN_bin2bn(q, q_len, NULL);
    dsa_g = BN_bin2bn(g, g_len, NULL);
    if (!dsa_p || !dsa_q || !dsa_g) {
        fprintf(stderr, "BN_bin2bn failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto out;
    }

    if (DSA_set0_pqg(dsa, dsa_p, dsa_q, dsa_g) != 1) {
        fprintf(stderr, "DSA_set0_pqg failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto out;
    }
    /* After successful DSA_set0_pqg, the BIGNUM pointers are owned by DSA object */
    dsa_p = dsa_q = dsa_g = NULL;

    dsa_pub_key = BN_bin2bn(pub_key, pub_key_len, NULL);
    if (!dsa_pub_key) {
        fprintf(stderr, "BN_bin2bn for pub_key failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto out;
    }

    if (DSA_set0_key(dsa, dsa_pub_key, NULL) != 1) {
        fprintf(stderr, "DSA_set0_key failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto out;
    }
    /* After successful DSA_set0_key, the BIGNUM pointer is owned by DSA object */
    dsa_pub_key = NULL;

    verify_status = DSA_verify(0, data, data_len, sig, sig_len, dsa);
    if (verify_status < 0) {
        fprintf(stderr, "DSA_verify failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto out;
    } else if (verify_status == 0) {
        // printf("Signature is invalid\n");
        ret = 1; // signature invalid
    } else {
        // printf("Signature is valid\n");
        ret = 0; // signature valid
    }

out:
    if (dsa) {
        DSA_free(dsa);
    }
    /* Free BIGNUMs only if they weren't transferred to DSA object */
    if (dsa_p) BN_free(dsa_p);
    if (dsa_q) BN_free(dsa_q);
    if (dsa_g) BN_free(dsa_g);
    if (dsa_pub_key) BN_free(dsa_pub_key);
    return ret;
}

int main(int argc, char *argv[])
{
    int ret = 0;
    unsigned char *p = NULL, *q = NULL, *g = NULL;
    int p_len = 0, q_len = 0, g_len = 0;
    unsigned char *pub_key = NULL, *priv_key = NULL;
    int pub_key_len = 0, priv_key_len = 0;
    unsigned char *data = (unsigned char *)"Test data for DSA signing";
    int data_len = strlen((char *)data);
    unsigned char *sig = NULL;
    int sig_len = 0;

    {
        // Generate DSA parameters p, q, g
        ret = call_dsa_gen_p_q_g(&p, &p_len, &q, &q_len, &g, &g_len);
        if (ret != 0) {
            fprintf(stderr, "call_dsa_gen_p_q_g failed\n");
            goto out;
        }

        printf("DSA parameters generated successfully:\n");
        printf("p (length %d): ", p_len);
        for (int i = 0; i < p_len; i++)
            printf("%02x", p[i]);
        printf("\n");

        printf("q (length %d): ", q_len);
        for (int i = 0; i < q_len; i++)
            printf("%02x", q[i]);
        printf("\n");

        printf("g (length %d): ", g_len);
        for (int i = 0; i < g_len; i++)
            printf("%02x", g[i]);
        printf("\n");
    }

    {
        // Generate DSA key pair using the generated parameters
        ret = call_dsa_gen_key(p, p_len, q, q_len, g, g_len,
                               &pub_key, &pub_key_len,
                               &priv_key, &priv_key_len);
        if (ret != 0) {
            fprintf(stderr, "call_dsa_gen_key failed\n");
            goto out;
        }

        printf("DSA key pair generated successfully:\n");
        printf("Public Key (length %d): ", pub_key_len);
        for (int i = 0; i < pub_key_len; i++)
            printf("%02x", pub_key[i]);
        printf("\n");

        printf("Private Key (length %d): ", priv_key_len);
        for (int i = 0; i < priv_key_len; i++)
            printf("%02x", priv_key[i]);
        printf("\n");
    }

    {
        // Sign data using the private key
        ret = call_dsa_sign(p, p_len, q, q_len, g, g_len,
                            priv_key, priv_key_len,
                            data, data_len,
                            &sig, &sig_len);
        if (ret != 0) {
            fprintf(stderr, "call_dsa_sign failed\n");
            goto out;
        }

        printf("Data signed successfully. Signature (length %d): ", sig_len);
        for (int i = 0; i < sig_len; i++)
            printf("%02x", sig[i]);
        printf("\n");
    }

    {
        // Verify the signature using the public key
        ret = call_dsa_verify(p, p_len, q, q_len, g, g_len,
                              pub_key, pub_key_len,
                              data, data_len,
                              sig, sig_len);
        if (ret < 0) {
            fprintf(stderr, "call_dsa_verify failed\n");
            goto out;
        } else if (ret == 1) {
            fprintf(stderr, "Signature is invalid\n");
            goto out;
        } else {
            printf("Signature is valid\n");
        }
    }


out:
    if (p) {
        free(p);
    }
    if (q) {
        free(q);
    }
    if (g) {
        free(g);
    }
    if (pub_key) {
        free(pub_key);
    }
    if (priv_key) {
        free(priv_key);
    }
    if (sig) {
        free(sig);
    }
    return ret;
}