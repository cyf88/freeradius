/*
 * mppe_keys.c
 *
 * Version:     $Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2002  Axis Communications AB
 * Copyright 2006  The FreeRADIUS server project
 * Authors: Henrik Eriksson <henriken@axis.com> & Lars Viklund <larsv@axis.com>
 */

RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#include "eap_tls.h"
#include <openssl/ssl.h>
#include <openssl/hmac.h>
#include <openssl/sgd.h>
#include <freeradius-devel/openssl3.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif

/*
 *	TLS P_hash from RFC 2246/5246 section 5
 */
static void P_hash(EVP_MD const *evp_md,
		   unsigned char const *secret, unsigned int secret_len,
		   unsigned char const *seed,   unsigned int seed_len,
		   unsigned char *out, unsigned int out_len)
{
	HMAC_CTX *ctx_a, *ctx_out;
	unsigned char a[EVP_MAX_MD_SIZE];
	unsigned int size = EVP_MAX_MD_SIZE;
	unsigned int digest_len;

	ctx_a = HMAC_CTX_new();
	ctx_out = HMAC_CTX_new();
	HMAC_Init_ex(ctx_a, secret, secret_len, evp_md, NULL);
	HMAC_Init_ex(ctx_out, secret, secret_len, evp_md, NULL);

	/* Calculate A(1) */
	HMAC_Update(ctx_a, seed, seed_len);
	HMAC_Final(ctx_a, a, &size);

	while (1) {
		/* Calculate next part of output */
		HMAC_Update(ctx_out, a, size);
		HMAC_Update(ctx_out, seed, seed_len);

		/* Check if last part */
		if (out_len < size) {
			digest_len = EVP_MAX_MD_SIZE;
			HMAC_Final(ctx_out, a, &digest_len);
			memcpy(out, a, out_len);
			break;
		}

		/* Place digest in output buffer */
		digest_len = EVP_MAX_MD_SIZE;
		HMAC_Final(ctx_out, out, &digest_len);
		HMAC_Init_ex(ctx_out, NULL, 0, NULL, NULL);
		out += size;
		out_len -= size;

		/* Calculate next A(i) */
		HMAC_Init_ex(ctx_a, NULL, 0, NULL, NULL);
		HMAC_Update(ctx_a, a, size);
		digest_len = EVP_MAX_MD_SIZE;
		HMAC_Final(ctx_a, a, &digest_len);
	}

	HMAC_CTX_free(ctx_a);
	HMAC_CTX_free(ctx_out);
	memset(a, 0, sizeof(a));
}

/*
 *	TLS PRF from RFC 2246 section 5
 */
static void PRF(unsigned char const *secret, unsigned int secret_len,
		unsigned char const *seed,   unsigned int seed_len,
		unsigned char *out, unsigned int out_len)
{
	uint8_t buf[out_len + (out_len % SHA_DIGEST_LENGTH)];
	unsigned int i;

	unsigned int len = (secret_len + 1) / 2;
	uint8_t const *s1 = secret;
	uint8_t const *s2 = secret + (secret_len - len);

	EVP_MD const *md5 = NULL;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	EVP_MD *md5_to_free = NULL;

	/*
	 *	If we are using OpenSSL >= 3.0 and FIPS mode is
	 *	enabled, we need to load the default provider in a
	 *	standalone context in order to access MD5.
	 */
	OSSL_LIB_CTX	*libctx = NULL;
	OSSL_PROVIDER	*default_provider = NULL;

	if (EVP_default_properties_is_fips_enabled(NULL)) {
		libctx = OSSL_LIB_CTX_new();
		default_provider = OSSL_PROVIDER_load(libctx, "default");

		if (!default_provider) {
			ERROR("Failed loading OpenSSL default provider.");
			return;
		}

		md5_to_free = EVP_MD_fetch(libctx, "MD5", NULL);
		if (!md5_to_free) {
			ERROR("Failed loading OpenSSL MD5 function.");
			return;
		}

		md5 = md5_to_free;
	} else {
		md5 = EVP_md5();
	}
#else
	md5 = EVP_md5();
#endif

	P_hash(md5, s1, len, seed, seed_len, out, out_len);
	P_hash(EVP_sha1(), s2, len, seed, seed_len, buf, out_len);

	for (i = 0; i < out_len; i++) {
		out[i] ^= buf[i];
	}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	if (libctx) {
		OSSL_PROVIDER_unload(default_provider);
		OSSL_LIB_CTX_free(libctx);
		EVP_MD_free(md5_to_free);
	}
#endif
}

/*
 *	TLS 1.2 PRF from RFC 5246 section 5
 */
static void PRFv12(unsigned char const *secret, unsigned int secret_len,
		   unsigned char const *seed,   unsigned int seed_len,
		   unsigned char *out, unsigned int out_len)
{
	P_hash(EVP_sha256(), secret, secret_len, seed, seed_len, out, out_len);
}

/*  EAP-FAST Pseudo-Random Function (T-PRF): RFC 4851, Section 5.5 */
void T_PRF(unsigned char const *secret, unsigned int secret_len,
	   char const *prf_label,
	   unsigned char const *seed,  unsigned int seed_len,
	   unsigned char *out, unsigned int out_len)
{
	size_t prf_size = strlen(prf_label);
	size_t pos;
	uint8_t	*buf;

	if (prf_size > 128) prf_size = 128;
	prf_size++;	/* include trailing zero */

	buf = talloc_size(NULL, SHA1_DIGEST_LENGTH + prf_size + seed_len + 2 + 1);

	memcpy(buf + SHA1_DIGEST_LENGTH, prf_label, prf_size);
	if (seed) memcpy(buf + SHA1_DIGEST_LENGTH + prf_size, seed, seed_len);
	*(uint16_t *)&buf[SHA1_DIGEST_LENGTH + prf_size + seed_len] = htons(out_len);
	buf[SHA1_DIGEST_LENGTH + prf_size + seed_len + 2] = 1;

	// T1 is just the seed
	fr_hmac_sha1(buf, buf + SHA1_DIGEST_LENGTH, prf_size + seed_len + 2 + 1, secret, secret_len);

#define MIN(a,b) (((a)>(b)) ? (b) : (a))
	memcpy(out, buf, MIN(out_len, SHA1_DIGEST_LENGTH));

	pos = SHA1_DIGEST_LENGTH;
	while (pos < out_len) {
		buf[SHA1_DIGEST_LENGTH + prf_size + seed_len + 2]++;

		fr_hmac_sha1(buf, buf, SHA1_DIGEST_LENGTH + prf_size + seed_len + 2 + 1, secret, secret_len);
		memcpy(&out[pos], buf, MIN(out_len - pos, SHA1_DIGEST_LENGTH));

		if (out_len - pos <= SHA1_DIGEST_LENGTH)
			break;

		pos += SHA1_DIGEST_LENGTH;
	}

	memset(buf, 0, SHA1_DIGEST_LENGTH + prf_size + seed_len + 2 + 1);
	talloc_free(buf);
}

#define EAPTLS_MPPE_KEY_LEN     32
#define EAPTLS_L2_KEY_LEN 16




int tls1_export_keying_material(SSL *s, unsigned char *out, size_t olen,
                                const char *label, size_t llen,
                                const unsigned char *context,
                                size_t contextlen, int use_context)
{
    unsigned char *val = NULL;
    size_t vallen = 0;
    size_t currentvalpos = 0;
    int rv;


    unsigned char client_random[1000] = {0};  // 最大长度取决于加密算法
    memset (client_random, 0x00, 1000);
    size_t client_random_size = SSL_get_client_random(s, client_random,1000);
    unsigned char server_random[1000] = {0};  // 最大长度取决于加密算法
    memset (server_random, 0x00, 1000);
    size_t server_random_size = SSL_get_server_random(s, server_random,1000);


    /*
     * construct PRF arguments we construct the PRF argument ourself rather
     * than passing separate values into the TLS PRF to ensure that the
     * concatenation of values does not create a prohibited label.
     */
    vallen = llen + SSL3_RANDOM_SIZE * 2;
    if (use_context) {
        vallen += 2 + contextlen;
    }

    val = OPENSSL_malloc(vallen);
    if (val == NULL)
        goto err2;
    currentvalpos = 0;
    memcpy(val + currentvalpos, (unsigned char *)label, llen);
    currentvalpos += llen;
    memcpy(val + currentvalpos, client_random, SSL3_RANDOM_SIZE);
    currentvalpos += SSL3_RANDOM_SIZE;
    memcpy(val + currentvalpos, server_random, SSL3_RANDOM_SIZE);
    currentvalpos += SSL3_RANDOM_SIZE;

    if (use_context) {
        val[currentvalpos] = (contextlen >> 8) & 0xff;
        currentvalpos++;
        val[currentvalpos] = contextlen & 0xff;
        currentvalpos++;
        if ((contextlen > 0) || (context != NULL)) {
            memcpy(val + currentvalpos, context, contextlen);
        }
    }

    /*
     * disallow prohibited labels note that SSL3_RANDOM_SIZE > max(prohibited
     * label len) = 15, so size of val > max(prohibited label len) = 15 and
     * the comparisons won't have buffer overflow
     */
    if (memcmp(val, TLS_MD_CLIENT_FINISH_CONST,
               TLS_MD_CLIENT_FINISH_CONST_SIZE) == 0)
        goto err1;
    if (memcmp(val, TLS_MD_SERVER_FINISH_CONST,
               TLS_MD_SERVER_FINISH_CONST_SIZE) == 0)
        goto err1;
    if (memcmp(val, TLS_MD_MASTER_SECRET_CONST,
               TLS_MD_MASTER_SECRET_CONST_SIZE) == 0)
        goto err1;
    if (memcmp(val, TLS_MD_EXTENDED_MASTER_SECRET_CONST,
               TLS_MD_EXTENDED_MASTER_SECRET_CONST_SIZE) == 0)
        goto err1;
    if (memcmp(val, TLS_MD_KEY_EXPANSION_CONST,
               TLS_MD_KEY_EXPANSION_CONST_SIZE) == 0)
        goto err1;

    SSL_SESSION *session = SSL_get_session(s);
    unsigned char master_key[1000] = {0};  // 最大长度取决于加密算法
    memset (master_key, 0x00, 1000);
    size_t master_key_length = SSL_SESSION_get_master_key(session, master_key, sizeof(master_key));
    if (master_key_length > 0) {
        DEBUG2("master key : %s",master_key ) ;
    }


//    rv = tls1_PRF(s,
//                  val, vallen,
//                  NULL, 0,
//                  NULL, 0,
//                  NULL, 0,
//                  NULL, 0,
//                  master_key, master_key_length,
//                  out, olen, 0);

    goto ret;
    err1:
    ERR_raise(ERR_LIB_SSL, SSL_R_TLS_ILLEGAL_EXPORTER_LABEL);
    rv = 0;
    goto ret;
    err2:
    ERR_raise(ERR_LIB_SSL, ERR_R_MALLOC_FAILURE);
    rv = 0;
    ret:
    OPENSSL_clear_free(val, vallen);
    return rv;
}

static unsigned char* sm4_cbc(unsigned char* key, size_t key_len,
                              unsigned char* iv,
                              unsigned char* in, size_t in_len,
                              size_t *out_len) {

    unsigned char *out = OPENSSL_malloc(in_len * 2);
    size_t outlen = 0;
    size_t tmp_len = 0;
    *out_len = 0;

    EVP_CIPHER_CTX *sm4_ctx =  EVP_CIPHER_CTX_new();
    if (sm4_ctx == NULL) {
      return 0;
    }
    const EVP_CIPHER *cipher = EVP_sm4_cbc();

    if (!EVP_CipherInit_ex(sm4_ctx, cipher, NULL, key, iv, 1)
        || !EVP_CIPHER_CTX_set_padding(sm4_ctx, 0)) {
        return 0;
    }

    if (!EVP_EncryptUpdate(sm4_ctx, out, (int *)&tmp_len, in, in_len)) {
        /* 错误处理 */
        EVP_CIPHER_CTX_free(sm4_ctx);
        return 0;
    }
    outlen = tmp_len;

    if (!EVP_EncryptFinal_ex(sm4_ctx, out + tmp_len, (int *)&tmp_len)) {
        EVP_CIPHER_CTX_free(sm4_ctx);
        return 0;
    }

    outlen += tmp_len;
    EVP_CIPHER_CTX_free(sm4_ctx);
    *out_len = outlen;
    return out;

}

/*
 *	Generate keys according to RFC 2716 and add to reply
 */
void eaptls_gen_mppe_keys(REQUEST *request, SSL *s, char const *label, uint8_t const *context, UNUSED size_t context_size)
{
	uint8_t out[4 * EAPTLS_MPPE_KEY_LEN];
	uint8_t *p;
	size_t len;

	len = strlen(label);

    SSL_SESSION *session = SSL_get_session(s);
    unsigned char master_key[1000] = {0};  // 最大长度取决于加密算法
    memset (master_key, 0x00, 1000);
    size_t master_key_length = SSL_SESSION_get_master_key(session, master_key, sizeof(master_key));
    if (master_key_length > 0) {
        DEBUG2("master key : %s",master_key ) ;
    }


//#if OPENSSL_VERSION_NUMBER >= 0x10001000L
//    if (tls1_export_keying_material(s, out, sizeof(out), label, len, context, context_size, context != NULL) != 1) {
//        ERROR("Failed generating keying material");
//        return;
//    }
//    if (SSL_export_keying_material(s, out, sizeof(out), label, len, context, context_size, context != NULL) != 1) {
//        ERROR("Failed generating keying material");
//        return;
//    }

//	if (SSL_export_keying_material(s, out, sizeof(out), label, len, NULL, 0, 0) != 1) {
//        ERROR("Failed generating keying material");
//		return;
//	}


//#else
    unsigned char client_random[1000] = {0};  // 最大长度取决于加密算法
    memset (client_random, 0x00, 1000);
    size_t client_random_size = SSL_get_client_random(s, client_random,1000);
    unsigned char server_random[1000] = {0};  // 最大长度取决于加密算法
    memset (server_random, 0x00, 1000);
    size_t server_random_size = SSL_get_server_random(s, server_random,1000);

	{
		uint8_t seed[64 + (2 * SSL3_RANDOM_SIZE) + (context ? 2 + context_size : 0)];
		uint8_t buf[4 * EAPTLS_MPPE_KEY_LEN];

		p = seed;

		memcpy(p, label, len);
		p += len;

		memcpy(p, client_random, SSL3_RANDOM_SIZE);
		p += SSL3_RANDOM_SIZE;
		len += SSL3_RANDOM_SIZE;

		memcpy(p, server_random, SSL3_RANDOM_SIZE);
		p += SSL3_RANDOM_SIZE;
		len += SSL3_RANDOM_SIZE;

		if (context) {
			/* cloned and reversed FR_PUT_LE16 */
			p[0] = ((uint16_t) (context_size)) >> 8;
			p[1] = ((uint16_t) (context_size)) & 0xff;
			p += 2;
			len += 2;
			memcpy(p, context, context_size);
			p += context_size;
			len += context_size;
		}

		PRF(master_key, master_key_length,
		    seed, len, out, sizeof(out));
	}
//#endif
    int out_len = sizeof(out);
	p = out;

    //封装avp
    unsigned char random_iv[EAPTLS_L2_KEY_LEN];
    RAND_bytes(random_iv, EAPTLS_L2_KEY_LEN);
    unsigned char *sm4_key_send = NULL;
    unsigned char *sm4_key_recv = NULL;
    size_t outlen;
    char* secret_key = request->client->secret;
    unsigned char  md_key[32] = {0};
    size_t mdlen = 0;

    if (!EVP_Q_digest(NULL, "SM3", NULL, secret_key, strlen(secret_key), md_key, &mdlen)) {
        /* 错误处理 */
        return;
    }


    pair_make_reply("Trans-Encryption-Way", "SM4-128-CBC", T_OP_SET); /*proxy unroutable*/
    eap_add_reply(request, "Trans-Encryption-Iv", random_iv, EAPTLS_L2_KEY_LEN);

    sm4_key_send =  sm4_cbc(md_key, EAPTLS_L2_KEY_LEN, random_iv, p, EAPTLS_L2_KEY_LEN, &outlen);

    p += EAPTLS_L2_KEY_LEN;
    sm4_key_recv =  sm4_cbc(md_key, EAPTLS_L2_KEY_LEN, random_iv, p, EAPTLS_L2_KEY_LEN, &outlen);

    p += EAPTLS_L2_KEY_LEN;

    eap_add_reply(request, "L2-Encryption-Key-Send", sm4_key_send, EAPTLS_L2_KEY_LEN);
    eap_add_reply(request, "L2-Encryption-Key-Recv", sm4_key_recv, EAPTLS_L2_KEY_LEN);
    eap_add_reply(request, "L2-Encryption-Iv-Send", p, EAPTLS_L2_KEY_LEN);
    p += EAPTLS_L2_KEY_LEN;
    eap_add_reply(request, "L2-Encryption-Iv-Recv", p, EAPTLS_L2_KEY_LEN);


//	eap_add_reply(request, "L2-Encryption-Key-Send", p, EAPTLS_MPPE_KEY_LEN);
//	p += EAPTLS_MPPE_KEY_LEN;
//	eap_add_reply(request, "MS-MPPE-Send-Key", p, EAPTLS_MPPE_KEY_LEN);
//
//	eap_add_reply(request, "EAP-MSK", out, 64);
//	eap_add_reply(request, "EAP-EMSK", out + 64, 64);
}


#define FR_TLS_PRF_CHALLENGE		"ttls challenge"

/*
 *	Generate the TTLS challenge
 *
 *	It's in the TLS module simply because it's only a few lines
 *	of code, and it needs access to the TLS PRF functions.
 */
void eapttls_gen_challenge(SSL *s, uint8_t *buffer, size_t size)
{
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
	if (SSL_export_keying_material(s, buffer, size, FR_TLS_PRF_CHALLENGE,
				       sizeof(FR_TLS_PRF_CHALLENGE)-1, NULL, 0, 0) != 1) {
		ERROR("Failed generating keying material");
	}
#else
	uint8_t out[32], buf[32];
	uint8_t seed[sizeof(FR_TLS_PRF_CHALLENGE)-1 + 2*SSL3_RANDOM_SIZE];
	uint8_t *p = seed;

	memcpy(p, FR_TLS_PRF_CHALLENGE, sizeof(FR_TLS_PRF_CHALLENGE)-1);
	p += sizeof(FR_TLS_PRF_CHALLENGE)-1;
	memcpy(p, s->s3->client_random, SSL3_RANDOM_SIZE);
	p += SSL3_RANDOM_SIZE;
	memcpy(p, s->s3->server_random, SSL3_RANDOM_SIZE);

	PRF(s->session->master_key, s->session->master_key_length,
	    seed, sizeof(seed), out, buf, sizeof(out));
	memcpy(buffer, out, size);
#endif
}

#define FR_TLS_EXPORTER_METHOD_ID	"EXPORTER_EAP_TLS_Method-Id"

/*
 *	Actually generates EAP-Session-Id, which is an internal server
 *	attribute.  Not all systems want to send EAP-Key-Name.
 */
void eaptls_gen_eap_key(eap_handler_t *handler)
{
	RADIUS_PACKET *packet = handler->request->reply;
	tls_session_t *tls_session = handler->opaque;
	SSL *s = tls_session->ssl;
	VALUE_PAIR *vp;
	uint8_t *buff, *p;
	uint8_t type = handler->type & 0xff;

	vp = fr_pair_afrom_num(packet, PW_EAP_SESSION_ID, 0);
	if (!vp) return;

	vp->vp_length = 1 + 2 * SSL3_RANDOM_SIZE;
	buff = p = talloc_array(vp, uint8_t, vp->vp_length);

	*p++ = type;

	switch (SSL_version(tls_session->ssl)) {
	case TLS1_VERSION:
	case TLS1_1_VERSION:
	case TLS1_2_VERSION:
    case NTLS_VERSION:
		SSL_get_client_random(s, p, SSL3_RANDOM_SIZE);
		p += SSL3_RANDOM_SIZE;
		SSL_get_server_random(s, p, SSL3_RANDOM_SIZE);
		break;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#ifdef TLS1_3_VERSION
	case TLS1_3_VERSION:
#endif
	default:
	{
		uint8_t const context[] = { type };

		if (SSL_export_keying_material(s, p, 2 * SSL3_RANDOM_SIZE,
					       FR_TLS_EXPORTER_METHOD_ID, sizeof(FR_TLS_EXPORTER_METHOD_ID)-1,
					       context, sizeof(context), 1) != 1) {
			ERROR("Failed generating keying material");
			return;
		}
	}
#endif
	}

	vp->vp_octets = buff;
	fr_pair_add(&packet->vps, vp);
}

/*
 *	Same as before, but for EAP-FAST the order of {server,client}_random is flipped
 */
void eap_fast_tls_gen_challenge(SSL *s, int version, uint8_t *buffer, size_t size, char const *prf_label)
{
	uint8_t *p;
	size_t len, master_key_len;
	uint8_t seed[128 + 2*SSL3_RANDOM_SIZE];
	uint8_t master_key[SSL_MAX_MASTER_KEY_LENGTH];

	len = strlen(prf_label);
	if (len > 128) len = 128;

	p = seed;
	memcpy(p, prf_label, len);
	p += len;
	SSL_get_server_random(s, p, SSL3_RANDOM_SIZE);
	p += SSL3_RANDOM_SIZE;
	SSL_get_client_random(s, p, SSL3_RANDOM_SIZE);
	p += SSL3_RANDOM_SIZE;

	master_key_len = SSL_SESSION_get_master_key(SSL_get_session(s), master_key, sizeof(master_key));

	if (version == TLS1_2_VERSION)
		PRFv12(master_key, master_key_len, seed, p - seed, buffer, size);
	else
		PRF(master_key, master_key_len, seed, p - seed, buffer, size);
}
