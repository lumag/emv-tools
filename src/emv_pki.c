#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "emv_pki.h"
#include "crypto_backend.h"

#include <stdlib.h>
#include <string.h>

static struct tlv empty_tlv = {.tag = 0x0, .len = 0, .value = NULL};

static unsigned char *emv_pki_decode_message(const struct capk *enc_pk,
		uint8_t msgtype,
		size_t *len,
		const struct tlv *cert_tlv,
		const struct tlv *exp_tlv,
		const struct tlv *rem_tlv,
		unsigned char *add_data, size_t add_data_len
		)
{
	struct crypto_pk *kcp;
	unsigned char *data;
	size_t data_len;

	if (!enc_pk)
		return NULL;

	if (!cert_tlv || !exp_tlv || !rem_tlv)
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

	struct crypto_hash *ch;
	ch = crypto_hash_open(enc_pk->hash_algo);
	if (!ch) {
		free(data);
		return NULL;
	}

	crypto_hash_write(ch, data + 1, data_len - 22);
	crypto_hash_write(ch, rem_tlv->value, rem_tlv->len);
	crypto_hash_write(ch, exp_tlv->value, exp_tlv->len);
	crypto_hash_write(ch, add_data, add_data_len);

	if (memcmp(data + data_len - 21, crypto_hash_read(ch), 20)) {
		crypto_hash_close(ch);
		free(data);
		return NULL;
	}

	crypto_hash_close(ch);

	*len = data_len;

	return data;
}


static struct capk *emv_pki_decode_message_2(const struct capk *enc_pk,
		const struct tlv *cert_tlv,
		const struct tlv *exp_tlv,
		const struct tlv *rem_tlv)
{
	unsigned char *data;
	size_t data_len;
	size_t pk_len;

	data = emv_pki_decode_message(enc_pk, 2, &data_len,
			cert_tlv,
			exp_tlv,
			rem_tlv ? rem_tlv : &empty_tlv,
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

	struct capk *pk = capk_new(pk_len, exp_tlv->len);

	memcpy(pk->rid, pk->rid, 5);
	pk->index = pk->index;

	pk->hash_algo = data[11];
	pk->pk_algo = data[12];
	pk->expire = (data[7] << 16) | (data[6] << 8) | 31;

	memcpy(pk->modulus, data + 15, data_len - 36);
	memcpy(pk->modulus + data_len - 36, rem_tlv->value, rem_tlv->len);
	memcpy(pk->exp, exp_tlv->value, exp_tlv->len);

	free(data);

	return pk;
}

static struct capk *emv_pki_decode_message_4(const struct capk *enc_pk,
		const struct tlv *cert_tlv,
		const struct tlv *exp_tlv,
		const struct tlv *rem_tlv,
		unsigned char *add_data, size_t add_data_len
		)
{
	unsigned char *data;
	size_t data_len;
	size_t pk_len;

	data = emv_pki_decode_message(enc_pk, 4, &data_len,
			cert_tlv,
			exp_tlv,
			rem_tlv ? rem_tlv : &empty_tlv,
			add_data, add_data_len);

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

	struct capk *pk = capk_new(pk_len, exp_tlv->len);

	memcpy(pk->rid, pk->rid, 5);
	pk->index = pk->index;

	pk->hash_algo = data[17];
	pk->pk_algo = data[18];
	pk->expire = (data[13] << 16) | (data[12] << 8) | 31;

	memcpy(pk->modulus, data + 21,
			pk_len < data_len - 42 ? pk_len : data_len - 42);
	memcpy(pk->modulus + data_len - 42, rem_tlv->value, rem_tlv->len);
	memcpy(pk->exp, exp_tlv->value, exp_tlv->len);

	free(data);

	return pk;
}

struct capk *emv_pki_recover_issuer_cert(const struct capk *pk, struct tlvdb *db)
{
	return emv_pki_decode_message_2(pk,
			tlvdb_get(db, 0x90, NULL),
			tlvdb_get(db, 0x9f32, NULL),
			tlvdb_get(db, 0x92, NULL));
}

struct capk *emv_pki_recover_icc_cert(const struct capk *pk, struct tlvdb *db, unsigned char *sda_data, size_t sda_data_len)
{
	return emv_pki_decode_message_4(pk,
			tlvdb_get(db, 0x9f46, NULL),
			tlvdb_get(db, 0x9f47, NULL),
			tlvdb_get(db, 0x9f48, NULL),
			sda_data, sda_data_len);
}

struct capk *emv_pki_recover_icc_pe_cert(const struct capk *pk, struct tlvdb *db)
{
	return emv_pki_decode_message_4(pk,
			tlvdb_get(db, 0x9f2d, NULL),
			tlvdb_get(db, 0x9f2e, NULL),
			tlvdb_get(db, 0x9f2f, NULL),
			NULL, 0);
}

struct tlvdb *emv_pki_recover_dac(const struct capk *enc_pk, const struct tlvdb *db, unsigned char *sda_data, size_t sda_data_len)
{
	size_t data_len;
	unsigned char *data = emv_pki_decode_message(enc_pk, 3, &data_len,
			tlvdb_get(db, 0x93, NULL),
			&empty_tlv,
			&empty_tlv,
			sda_data, sda_data_len);

	if (!data)
		return NULL;

	struct tlvdb *dac_db = tlvdb_fixed(0x459f, 2, data+3);

	free(data);

	return dac_db;
}

struct tlvdb *emv_pki_recover_idn(const struct capk *enc_pk, const struct tlvdb *db, unsigned char *dyn_data, size_t dyn_data_len)
{
	size_t data_len;
	unsigned char *data = emv_pki_decode_message(enc_pk, 5, &data_len,
			tlvdb_get(db, 0x9f4b, NULL),
			&empty_tlv,
			&empty_tlv,
			dyn_data, dyn_data_len);

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

	struct tlvdb *idn_db = tlvdb_fixed(0x4c9f, idn_len, data + 5);
	free(data);

	return idn_db;
}
