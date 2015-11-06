/*
 * libopenemv - a library to work with EMV family of smart cards
 * Copyright (C) 2015 Dmitry Eremin-Solenikov
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "openemv/emv_pki_priv.h"
#include "openemv/crypto.h"

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

struct emv_pk *emv_pki_make_ca(const struct crypto_pk *cp,
		const unsigned char *rid, unsigned char index,
		unsigned int expire, enum crypto_algo_hash hash_algo)
{
	size_t modlen, explen;
	unsigned char *mod, *exp;

	if (!rid)
		return NULL;

	mod = crypto_pk_get_parameter(cp, 0, &modlen);
	exp = crypto_pk_get_parameter(cp, 1, &explen);

	if (!mod || !modlen || !exp || !explen) {
		free(mod);
		free(exp);

		return NULL;
	}

	struct emv_pk *pk = emv_pk_new(modlen, explen);
	memcpy(pk->rid, rid, 5);
	pk->index = index;
	pk->expire = expire;
	pk->pk_algo = crypto_pk_get_algo(cp);
	pk->hash_algo = hash_algo;
	memcpy(pk->modulus, mod, modlen);
	memcpy(pk->exp, exp, explen);

	free(mod);
	free(exp);

	struct crypto_hash *ch = crypto_hash_open(pk->hash_algo);
	if (!ch)
		return false;

	crypto_hash_write(ch, pk->rid, sizeof(pk->rid));
	crypto_hash_write(ch, &pk->index, 1);
	crypto_hash_write(ch, pk->modulus, pk->mlen);
	crypto_hash_write(ch, pk->exp, pk->elen);

	unsigned char *h = crypto_hash_read(ch);
	if (!h) {
		crypto_hash_close(ch);
		emv_pk_free(pk);

		return NULL;
	}

	memcpy(pk->hash, h, crypto_hash_get_size(ch));
	crypto_hash_close(ch);

	return pk;
}

static struct tlvdb *emv_pki_sign_message(const struct crypto_pk *cp,
		tlv_tag_t cert_tag, tlv_tag_t rem_tag,
		const unsigned char *msg, size_t msg_len,
		... /* A list of buffer-len pairs, end with NULL buffer */
		)
{
	size_t tmp_len = (crypto_pk_get_nbits(cp) + 7) / 8;
	unsigned char *tmp = malloc(tmp_len);
	if (!tmp)
		return NULL;

	// XXX
	struct crypto_hash *ch = crypto_hash_open(HASH_SHA_1);
	if (!ch) {
		free(tmp);

		return NULL;
	}

	tmp[0] = 0x6a;
	tmp[tmp_len - 1] = 0xbc;

	const unsigned char *rem;
	size_t rem_len;
	size_t hash_len = crypto_hash_get_size(ch);
	size_t part_len = tmp_len - 2 - hash_len;
	if (part_len < msg_len) {
		memcpy(tmp + 1, msg, part_len);
		rem = msg + part_len;
		rem_len = msg_len - part_len;
	} else {
		memcpy(tmp + 1, msg, msg_len);
		memset(tmp + 1 + msg_len, 0xbb, part_len - msg_len);
		rem = NULL;
		rem_len = 0;
	}
	crypto_hash_write(ch, tmp + 1, part_len);
	crypto_hash_write(ch, rem, rem_len);

	va_list vl;
	va_start(vl, msg_len);
	while (true) {
		size_t add_data_len;
		const unsigned char *add_data = va_arg(vl, const unsigned char *);
		if (!add_data)
			break;

		add_data_len = va_arg(vl, size_t);
		crypto_hash_write(ch, add_data, add_data_len);
	}
	va_end(vl);

	unsigned char *h = crypto_hash_read(ch);
	if (!h) {
		crypto_hash_close(ch);
		free(tmp);

		return NULL;
	}

	memcpy(tmp + 1 + part_len, h, hash_len);
	crypto_hash_close(ch);

	size_t cert_len;
	unsigned char *cert = crypto_pk_decrypt(cp, tmp, tmp_len, &cert_len);
	free(tmp);

	if (!cert)
		return NULL;

	struct tlvdb *db = tlvdb_fixed(cert_tag, cert_len, cert);
	free(cert);
	if (!db)
		return NULL;

	if (rem) {
		struct tlvdb *rdb = tlvdb_fixed(rem_tag, rem_len, rem);
		if (!rdb) {
			tlvdb_free(db);

			return NULL;
		}
		tlvdb_add(db, rdb);
	}

	return db;
}

struct tlvdb *emv_pki_sign_issuer_cert(const struct crypto_pk *cp, struct emv_pk *issuer_pk)
{
	unsigned pos = 0;
	unsigned char *msg = malloc(1 + 4 + 2 + 3 + 1 + 1 + 1 + 1 + issuer_pk->mlen);

	if (!msg)
		return NULL;

	msg[pos++] = 2;
	memcpy(msg + pos, issuer_pk->pan, 4); pos += 4;
	msg[pos++] = (issuer_pk->expire >> 8) & 0xff;
	msg[pos++] = (issuer_pk->expire >> 16) & 0xff;
	memcpy(msg + pos, issuer_pk->serial, 3); pos += 3;
	msg[pos++] = issuer_pk->hash_algo;
	msg[pos++] = issuer_pk->pk_algo;
	msg[pos++] = issuer_pk->mlen;
	msg[pos++] = issuer_pk->elen;
	memcpy(msg + pos, issuer_pk->modulus, issuer_pk->mlen);
	pos += issuer_pk->mlen;

	struct tlvdb *db = emv_pki_sign_message(cp,
			0x90, 0x92,
			msg, pos,
			issuer_pk->exp, issuer_pk->elen,
			NULL, 0);
	free(msg);
	if (!db)
		return NULL;

	tlvdb_add(db, tlvdb_fixed(0x9f32, issuer_pk->elen, issuer_pk->exp));

	return db;
}

struct tlvdb *emv_pki_sign_icc_cert(const struct crypto_pk *cp, struct emv_pk *icc_pk, const unsigned char *sda_data, size_t sda_data_len)
{
	unsigned pos = 0;
	unsigned char *msg = malloc(1 + 10 + 2 + 3 + 1 + 1 + 1 + 1 + icc_pk->mlen);

	if (!msg)
		return NULL;

	msg[pos++] = 4;
	memcpy(msg + pos, icc_pk->pan, 10); pos += 10;
	msg[pos++] = (icc_pk->expire >> 8) & 0xff;
	msg[pos++] = (icc_pk->expire >> 16) & 0xff;
	memcpy(msg + pos, icc_pk->serial, 3); pos += 3;
	msg[pos++] = icc_pk->hash_algo;
	msg[pos++] = icc_pk->pk_algo;
	msg[pos++] = icc_pk->mlen;
	msg[pos++] = icc_pk->elen;
	memcpy(msg + pos, icc_pk->modulus, icc_pk->mlen);
	pos += icc_pk->mlen;

	struct tlvdb *db = emv_pki_sign_message(cp,
			0x9f46, 0x9f48,
			msg, pos,
			icc_pk->exp, icc_pk->elen,
			sda_data, sda_data_len,
			NULL, 0);
	free(msg);
	if (!db)
		return NULL;

	tlvdb_add(db, tlvdb_fixed(0x9f47, icc_pk->elen, icc_pk->exp));

	return db;
}

struct tlvdb *emv_pki_sign_icc_pe_cert(const struct crypto_pk *cp, struct emv_pk *icc_pe_pk)
{
	unsigned pos = 0;
	unsigned char *msg = malloc(1 + 10 + 2 + 3 + 1 + 1 + 1 + 1 + icc_pe_pk->mlen);

	if (!msg)
		return NULL;

	msg[pos++] = 4;
	memcpy(msg + pos, icc_pe_pk->pan, 10); pos += 10;
	msg[pos++] = (icc_pe_pk->expire >> 8) & 0xff;
	msg[pos++] = (icc_pe_pk->expire >> 16) & 0xff;
	memcpy(msg + pos, icc_pe_pk->serial, 3); pos += 3;
	msg[pos++] = icc_pe_pk->hash_algo;
	msg[pos++] = icc_pe_pk->pk_algo;
	msg[pos++] = icc_pe_pk->mlen;
	msg[pos++] = icc_pe_pk->elen;
	memcpy(msg + pos, icc_pe_pk->modulus, icc_pe_pk->mlen);
	pos += icc_pe_pk->mlen;

	struct tlvdb *db = emv_pki_sign_message(cp,
			0x9f2d, 0x9f2f,
			msg, pos,
			icc_pe_pk->exp, icc_pe_pk->elen,
			NULL, 0);
	free(msg);
	if (!db)
		return NULL;

	tlvdb_add(db, tlvdb_fixed(0x9f2e, icc_pe_pk->elen, icc_pe_pk->exp));

	return db;
}

struct tlvdb *emv_pki_sign_dac(const struct crypto_pk *cp, const unsigned char *dac, const unsigned char *sda_data, size_t sda_data_len)
{
	unsigned pos = 0;
	unsigned char *msg = malloc(1+1+2);

	if (!msg)
		return NULL;

	msg[pos++] = 3;
	msg[pos++] = HASH_SHA_1;
	msg[pos++] = dac[0];
	msg[pos++] = dac[1];

	struct tlvdb *db = emv_pki_sign_message(cp,
			0x93, 0,
			msg, pos,
			sda_data, sda_data_len,
			NULL, 0);

	free(msg);

	return db;
}

struct tlvdb *emv_pki_sign_idn(const struct crypto_pk *cp, const unsigned char *idn, size_t idn_len, const unsigned char *dyn_data, size_t dyn_data_len)
{
	unsigned pos = 0;
	unsigned char *msg = malloc(1+1+1+1+idn_len);

	if (!msg)
		return NULL;

	msg[pos++] = 5;
	msg[pos++] = HASH_SHA_1;
	msg[pos++] = idn_len + 1;
	msg[pos++] = idn_len;
	memcpy(msg+pos, idn, idn_len); pos += idn_len;

	struct tlvdb *db = emv_pki_sign_message(cp,
			0x9f4b, 0,
			msg, pos,
			dyn_data, dyn_data_len,
			NULL, 0);

	free(msg);

	return db;
}
