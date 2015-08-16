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

#include "openemv/emv_pki.h"
#include "openemv/crypto.h"

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

static const unsigned char empty_tlv_value[] = {};
static const struct tlv empty_tlv = {.tag = 0x0, .len = 0, .value = empty_tlv_value};

static size_t emv_pki_hash_psn[256] = { 0, 0, 11, 2, 17, 2, };

static unsigned char *emv_pki_decode_message(const struct emv_pk *enc_pk,
		uint8_t msgtype,
		size_t *len,
		const struct tlv *cert_tlv,
		... /* A list of buffer-len pairs, end with NULL buffer */
		)
{
	struct crypto_pk *kcp;
	unsigned char *data;
	size_t data_len;
	va_list vl;

	if (!enc_pk)
		return NULL;

	if (!cert_tlv)
		return NULL;

	if (cert_tlv->len != enc_pk->mlen)
		return NULL;

	kcp = crypto_pk_open(enc_pk->pk_algo,
			enc_pk->modulus, enc_pk->mlen,
			enc_pk->exp, enc_pk->elen);
	if (!kcp)
		return NULL;

	data = crypto_pk_encrypt(kcp, cert_tlv->value, cert_tlv->len, &data_len);
	crypto_pk_close(kcp);

	if (data[data_len-1] != 0xbc || data[0] != 0x6a || data[1] != msgtype) {
		free(data);
		return NULL;
	}

	size_t hash_pos = emv_pki_hash_psn[msgtype];
	if (hash_pos == 0 || hash_pos > data_len){
		free(data);
		return NULL;
	}

	struct crypto_hash *ch;
	ch = crypto_hash_open(data[hash_pos]);
	if (!ch) {
		free(data);
		return NULL;
	}

	crypto_hash_write(ch, data + 1, data_len - 22);

	va_start(vl, cert_tlv);
	while (true) {
		size_t add_data_len;
		const unsigned char *add_data = va_arg(vl, const unsigned char *);
		if (!add_data)
			break;

		add_data_len = va_arg(vl, size_t);
		crypto_hash_write(ch, add_data, add_data_len);
	}
	va_end(vl);

	if (memcmp(data + data_len - 21, crypto_hash_read(ch), 20)) {
		crypto_hash_close(ch);
		free(data);
		return NULL;
	}

	crypto_hash_close(ch);

	*len = data_len;

	return data;
}


static struct emv_pk *emv_pki_decode_message_2(const struct emv_pk *enc_pk,
		const struct tlv *cert_tlv,
		const struct tlv *exp_tlv,
		const struct tlv *rem_tlv)
{
	unsigned char *data;
	size_t data_len;
	size_t pk_len;

	if (!cert_tlv || !exp_tlv)
		return NULL;

	if (!rem_tlv)
		rem_tlv = &empty_tlv;

	data = emv_pki_decode_message(enc_pk, 2, &data_len,
			cert_tlv,
			rem_tlv->value, rem_tlv->len,
			exp_tlv->value, exp_tlv->len,
			NULL, 0);
	if (!data)
		return NULL;


	/* Perform the rest of checks here */


	pk_len = data[13];
	/* Just to be sure -- not required by the standard ?! */
	if (pk_len != data_len - 36 + rem_tlv->len) {
		free(data);
		return NULL;
	}

	if (exp_tlv->len != data[14]) {
		free(data);
		return NULL;
	}

	struct emv_pk *pk = emv_pk_new(pk_len, exp_tlv->len);

	memcpy(pk->rid, enc_pk->rid, 5);
	pk->index = enc_pk->index;

	pk->hash_algo = data[11];
	pk->pk_algo = data[12];
	pk->expire = (data[7] << 16) | (data[6] << 8) | 31;
	memcpy(pk->serial, data + 8, 3);

	memcpy(pk->modulus, data + 15, data_len - 36);
	memcpy(pk->modulus + data_len - 36, rem_tlv->value, rem_tlv->len);
	memcpy(pk->exp, exp_tlv->value, exp_tlv->len);

	free(data);

	return pk;
}

static struct emv_pk *emv_pki_decode_message_4(const struct emv_pk *enc_pk,
		const struct tlv *cert_tlv,
		const struct tlv *exp_tlv,
		const struct tlv *rem_tlv,
		const unsigned char *add_data, size_t add_data_len
		)
{
	unsigned char *data;
	size_t data_len;
	size_t pk_len;

	if (!cert_tlv || !exp_tlv)
		return NULL;

	if (!rem_tlv)
		rem_tlv = &empty_tlv;

	data = emv_pki_decode_message(enc_pk, 4, &data_len,
			cert_tlv,
			rem_tlv->value, rem_tlv->len,
			exp_tlv->value, exp_tlv->len,
			add_data, add_data_len,
			NULL, 0);

	if (!data)
		return NULL;


	/* Perform the rest of checks here */

	pk_len = data[19];
	if (pk_len > data_len - 42 + rem_tlv->len) {
		free(data);
		return NULL;
	}

	if (exp_tlv->len != data[20]) {
		free(data);
		return NULL;
	}

	struct emv_pk *pk = emv_pk_new(pk_len, exp_tlv->len);

	memcpy(pk->rid, enc_pk->rid, 5);
	pk->index = enc_pk->index;

	pk->hash_algo = data[17];
	pk->pk_algo = data[18];
	pk->expire = (data[13] << 16) | (data[12] << 8) | 31;
	memcpy(pk->serial, data + 14, 3);

	memcpy(pk->modulus, data + 21,
			pk_len < data_len - 42 ? pk_len : data_len - 42);
	memcpy(pk->modulus + data_len - 42, rem_tlv->value, rem_tlv->len);
	memcpy(pk->exp, exp_tlv->value, exp_tlv->len);

	free(data);

	return pk;
}

struct emv_pk *emv_pki_recover_issuer_cert(const struct emv_pk *pk, struct tlvdb *db)
{
	return emv_pki_decode_message_2(pk,
			tlvdb_get(db, 0x90, NULL),
			tlvdb_get(db, 0x9f32, NULL),
			tlvdb_get(db, 0x92, NULL));
}

struct emv_pk *emv_pki_recover_icc_cert(const struct emv_pk *pk, struct tlvdb *db, const unsigned char *sda_data, size_t sda_data_len)
{
	return emv_pki_decode_message_4(pk,
			tlvdb_get(db, 0x9f46, NULL),
			tlvdb_get(db, 0x9f47, NULL),
			tlvdb_get(db, 0x9f48, NULL),
			sda_data, sda_data_len);
}

struct emv_pk *emv_pki_recover_icc_pe_cert(const struct emv_pk *pk, struct tlvdb *db)
{
	return emv_pki_decode_message_4(pk,
			tlvdb_get(db, 0x9f2d, NULL),
			tlvdb_get(db, 0x9f2e, NULL),
			tlvdb_get(db, 0x9f2f, NULL),
			NULL, 0);
}

struct tlvdb *emv_pki_recover_dac(const struct emv_pk *enc_pk, const struct tlvdb *db, const unsigned char *sda_data, size_t sda_data_len)
{
	size_t data_len;
	unsigned char *data = emv_pki_decode_message(enc_pk, 3, &data_len,
			tlvdb_get(db, 0x93, NULL),
			sda_data, sda_data_len,
			NULL, 0);

	if (!data)
		return NULL;

	struct tlvdb *dac_db = tlvdb_fixed(0x9f45, 2, data+3);

	free(data);

	return dac_db;
}

struct tlvdb *emv_pki_recover_idn(const struct emv_pk *enc_pk, const struct tlvdb *db, const unsigned char *dyn_data, size_t dyn_data_len)
{
	size_t data_len;
	unsigned char *data = emv_pki_decode_message(enc_pk, 5, &data_len,
			tlvdb_get(db, 0x9f4b, NULL),
			dyn_data, dyn_data_len,
			NULL, 0);

	if (!data)
		return NULL;

	if (data[3] < 2 || data[3] > data_len - 25) {
		free(data);
		return NULL;
	}

	size_t idn_len = data[4];
	if (idn_len > data[3] - 1) {
		free(data);
		return NULL;
	}

	struct tlvdb *idn_db = tlvdb_fixed(0x9f4c, idn_len, data + 5);
	free(data);

	return idn_db;
}

static bool tlv_hash(void *data, const struct tlv *tlv)
{
	struct crypto_hash *ch = data;
	size_t tag_len;
	unsigned char *tag;

	if (tlv_is_constructed(tlv))
		return true;

	if (tlv->tag == 0x9f4b)
		return true;

	tag = tlv_encode(tlv, &tag_len);
	crypto_hash_write(ch, tag, tag_len);
	free(tag);

	return true;
}

struct tlvdb *emv_pki_perform_cda(const struct emv_pk *enc_pk, const struct tlvdb *db,
		const struct tlvdb *this_db,
		const unsigned char *pdol_data, size_t pdol_data_len,
		const unsigned char *crm1_data, size_t crm1_data_len,
		const unsigned char *crm2_data, size_t crm2_data_len)
{
	const struct tlv *un_tlv = tlvdb_get(db, 0x9f37, NULL);
	const struct tlv *cid_tlv = tlvdb_get(this_db, 0x9f27, NULL);

	if (!un_tlv || !cid_tlv)
		return NULL;

	size_t data_len;
	unsigned char *data = emv_pki_decode_message(enc_pk, 5, &data_len,
			tlvdb_get(this_db, 0x9f4b, NULL),
			un_tlv->value, un_tlv->len,
			NULL, 0);
	if (!data)
		return NULL;

	if (data[3] < 30 || data[3] > data_len - 25) {
		free(data);
		return NULL;
	}

	if (!cid_tlv || cid_tlv->len != 1 || cid_tlv->value[0] != data[5 + data[4]]) {
		free(data);
		return NULL;
	}

	struct crypto_hash *ch;
	ch = crypto_hash_open(enc_pk->hash_algo);
	if (!ch) {
		free(data);
		return NULL;
	}

	crypto_hash_write(ch, pdol_data, pdol_data_len);
	crypto_hash_write(ch, crm1_data, crm1_data_len);
	crypto_hash_write(ch, crm2_data, crm2_data_len);

	tlvdb_visit(this_db, tlv_hash, ch);

	if (memcmp(data + 5 + data[4] + 1 + 8, crypto_hash_read(ch), 20)) {
		crypto_hash_close(ch);
		free(data);
		return NULL;
	}
	crypto_hash_close(ch);

	size_t idn_len = data[4];
	if (idn_len > data[3] - 1) {
		free(data);
		return NULL;
	}

	struct tlvdb *idn_db = tlvdb_fixed(0x9f4c, idn_len, data + 5);
	free(data);

	return idn_db;
}
