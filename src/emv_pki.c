#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "emv_pki.h"
#include "crypto_backend.h"

#include <stdlib.h>
#include <string.h>

static struct tlv empty_rem_tlv = {.tag = 0x92, .len = 0, .value = NULL};

struct capk *emv_pki_recover_issuer_cert(const struct capk *pk, struct tlvdb *db)
{
	struct crypto_pk *kcp;
	unsigned char *issuer_data;
	size_t issuer_data_len;
	size_t issuer_pk_len;

	const struct tlv *issuer_cert_tlv = tlvdb_get(db, 0x90, NULL);
	const struct tlv *issuer_rem_tlv = tlvdb_get(db, 0x92, NULL);
	const struct tlv *issuer_exp_tlv = tlvdb_get(db, 0x329f, NULL);

	if (!pk)
		return NULL;

	if (!issuer_cert_tlv || !issuer_exp_tlv)
		return NULL;

	if (!issuer_rem_tlv)
		issuer_rem_tlv = &empty_rem_tlv;

	if (issuer_cert_tlv->len != pk->mlen)
		return NULL;

	kcp = crypto_pk_open(pk->pk_algo,
			pk->modulus, pk->mlen,
			pk->exp, pk->elen);
	if (!kcp)
		return NULL;

	issuer_data = crypto_pk_encrypt(kcp, issuer_cert_tlv->value, issuer_cert_tlv->len, &issuer_data_len);
	crypto_pk_close(kcp);

	if (issuer_data[issuer_data_len-1] != 0xbc || issuer_data[0] != 0x6a || issuer_data[1] != 0x02) {
		free(issuer_data);
		return NULL;
	}

	struct crypto_hash *ch;
	ch = crypto_hash_open(pk->hash_algo);
	if (!ch) {
		free(issuer_data);
		return NULL;
	}

	crypto_hash_write(ch, issuer_data + 1, issuer_data_len - 22);
	crypto_hash_write(ch, issuer_rem_tlv->value, issuer_rem_tlv->len);
	crypto_hash_write(ch, issuer_exp_tlv->value, issuer_exp_tlv->len);

	if (memcmp(issuer_data + issuer_data_len - 21, crypto_hash_read(ch), 20)) {
		crypto_hash_close(ch);
		free(issuer_data);
		return NULL;
	}

	crypto_hash_close(ch);

	/* Perform the rest of checks here */


	issuer_pk_len = issuer_data[13];
	/* Just to be sure -- not required by the standard ?! */
	if (issuer_pk_len != issuer_data_len - 36 + issuer_rem_tlv->len) {
		free(issuer_data);
		return NULL;
	}

	if (issuer_exp_tlv->len != issuer_data[14]) {
		free(issuer_data);
		return NULL;
	}

	struct capk *issuer_pk = capk_new(issuer_pk_len, issuer_exp_tlv->len);

	memcpy(issuer_pk->rid, pk->rid, 5);
	issuer_pk->index = pk->index;

	issuer_pk->hash_algo = issuer_data[11];
	issuer_pk->pk_algo = issuer_data[12];
	issuer_pk->expire = (issuer_data[7] << 16) | (issuer_data[6] << 8) | 31;

	memcpy(issuer_pk->modulus, issuer_data + 15, issuer_data_len - 36);
	memcpy(issuer_pk->modulus + issuer_data_len - 36, issuer_rem_tlv->value, issuer_rem_tlv->len);
	memcpy(issuer_pk->exp, issuer_exp_tlv->value, issuer_exp_tlv->len);

	free(issuer_data);

	return issuer_pk;
}

struct capk *emv_pki_recover_icc_cert(const struct capk *pk, struct tlvdb *db, unsigned char *sda_data, size_t sda_len)
{
	struct crypto_pk *kcp;
	unsigned char *icc_data;
	size_t icc_data_len;
	size_t icc_pk_len;

	const struct tlv *icc_cert_tlv = tlvdb_get(db, 0x469f, NULL);
	const struct tlv *icc_rem_tlv = tlvdb_get(db, 0x489f, NULL);
	const struct tlv *icc_exp_tlv = tlvdb_get(db, 0x479f, NULL);

	if (!pk)
		return NULL;

	if (!icc_cert_tlv || !icc_exp_tlv)
		return NULL;

	if (!icc_rem_tlv)
		icc_rem_tlv = &empty_rem_tlv;

	if (icc_cert_tlv->len != pk->mlen)
		return NULL;

	kcp = crypto_pk_open(pk->pk_algo,
			pk->modulus, pk->mlen,
			pk->exp, pk->elen);
	if (!kcp)
		return NULL;

	icc_data = crypto_pk_encrypt(kcp, icc_cert_tlv->value, icc_cert_tlv->len, &icc_data_len);
	crypto_pk_close(kcp);

	if (icc_data[icc_data_len-1] != 0xbc || icc_data[0] != 0x6a || icc_data[1] != 0x04) {
		free(icc_data);
		return NULL;
	}

	struct crypto_hash *ch;
	ch = crypto_hash_open(pk->hash_algo);
	if (!ch) {
		free(icc_data);
		return NULL;
	}

	crypto_hash_write(ch, icc_data + 1, icc_data_len - 22);
	crypto_hash_write(ch, icc_rem_tlv->value, icc_rem_tlv->len);
	crypto_hash_write(ch, icc_exp_tlv->value, icc_exp_tlv->len);
	crypto_hash_write(ch, sda_data, sda_len);

	if (memcmp(icc_data + icc_data_len - 21, crypto_hash_read(ch), 20)) {
		crypto_hash_close(ch);
		free(icc_data);
		return NULL;
	}

	crypto_hash_close(ch);

	/* Perform the rest of checks here */

	icc_pk_len = icc_data[19];
	if (icc_pk_len > icc_data_len - 42 + icc_rem_tlv->len) {
		free(icc_data);
		return NULL;
	}

	if (icc_exp_tlv->len != icc_data[20]) {
		free(icc_data);
		return NULL;
	}

	struct capk *icc_pk = capk_new(icc_pk_len, icc_exp_tlv->len);

	memcpy(icc_pk->rid, pk->rid, 5);
	icc_pk->index = pk->index;

	icc_pk->hash_algo = icc_data[17];
	icc_pk->pk_algo = icc_data[18];
	icc_pk->expire = (icc_data[13] << 16) | (icc_data[12] << 8) | 31;

	memcpy(icc_pk->modulus, icc_data + 21,
			icc_pk_len < icc_data_len - 42 ? icc_pk_len : icc_data_len - 42);
	memcpy(icc_pk->modulus + icc_data_len - 42, icc_rem_tlv->value, icc_rem_tlv->len);
	memcpy(icc_pk->exp, icc_exp_tlv->value, icc_exp_tlv->len);

	free(icc_data);

	return icc_pk;
}
