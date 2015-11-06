/*
 * emv-tools - a set of tools to work with EMV family of smart cards
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

#include "openemv/crypto.h"
#include "openemv/emv_pk.h"
#include "openemv/emv_pki.h"
#include "openemv/emv_pki_priv.h"
#include "openemv/dump.h"

#include <string.h>

static const unsigned char rid[5] = {0xa0, 0x00, 0x00, 0x00, 0x00};
static const unsigned char caidx = 1;
static const unsigned char sdad[] = {
	0xde, 0xad, 0xbe, 0xaf, 0xca, 0xfe, 0xfe, 0xed,
};

const unsigned char dd1[] = {
	0x00, 0x00, 0x00, 0x00,
};

static const unsigned char dac[] = {
	0x31, 0x32,
};

static const unsigned char idn[] = {
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
};

static int test_emv_pki_make_ca(struct crypto_pk *cp)
{
	int ret = 1;
	struct emv_pk *pk = emv_pki_make_ca(cp, rid, caidx, 0x000000, HASH_SHA_1);
	if (!pk)
		goto out;

	if (!emv_pk_verify(pk))
		goto out;

	ret = 0;

out:
	emv_pk_free(pk);

	return ret;
}

static struct emv_pk *make_issuer_pk(struct crypto_pk *cp)
{
	struct emv_pk *ipk = emv_pki_make_ca(cp, rid, caidx, 0x231231, HASH_SHA_1);

	if (!ipk)
		return NULL;

	ipk->serial[0] = 0x12;
	ipk->serial[1] = 0x34;
	ipk->serial[2] = 0x56;
	memset(ipk->pan, 0xff, 10);
	ipk->pan[0] = 0x12;
	ipk->pan[1] = 0x34;
	ipk->pan[2] = 0x5f;

	return ipk;
}

static struct emv_pk *make_icc_pk(struct crypto_pk *cp)
{
	struct emv_pk *ipk = emv_pki_make_ca(cp, rid, caidx, 0x231231, HASH_SHA_1);

	if (!ipk)
		return NULL;

	ipk->serial[0] = 0xde;
	ipk->serial[1] = 0xde;
	ipk->serial[2] = 0xde;
	memset(ipk->pan, 0xff, 10);
	ipk->pan[0] = 0x12;
	ipk->pan[1] = 0x34;
	ipk->pan[2] = 0x56;
	ipk->pan[3] = 0x78;
	ipk->pan[4] = 0x89;
	ipk->pan[5] = 0x78;
	ipk->pan[6] = 0x56;
	ipk->pan[7] = 0x34;
	ipk->pan[8] = 0x12;

	return ipk;
}

static int test_emv_pki_sign_issuer_cert(struct crypto_pk *cp, struct crypto_pk *icp)
{
	int ret = 1;
	struct emv_pk *pk = emv_pki_make_ca(cp, rid, caidx, 0x000000, HASH_SHA_1);
	if (!pk)
		return ret;

	struct emv_pk *ipk = make_issuer_pk(icp);
	if (!ipk)
		goto out;

	struct tlvdb *db = emv_pki_sign_issuer_cert(cp, ipk);
	if (!db)
		goto out2;
	tlvdb_add(db, tlvdb_fixed(0x5a, 8, ipk->pan));

	struct emv_pk *rpk = emv_pki_recover_issuer_cert(pk, db);
	if (!rpk)
		goto out3;

	if (memcmp(rpk->rid, ipk->rid, 5) ||
	    rpk->index != ipk->index ||
	    rpk->hash_algo != ipk->hash_algo ||
	    rpk->pk_algo != ipk->pk_algo ||
	    rpk->expire != ipk->expire ||
	    memcmp(rpk->serial, ipk->serial, 3) ||
	    memcmp(rpk->pan, ipk->pan, 10) ||
	    rpk->mlen != ipk->mlen ||
	    memcmp(rpk->modulus, ipk->modulus, rpk->mlen) ||
	    rpk->elen != ipk->elen ||
	    memcmp(rpk->exp, ipk->exp, rpk->elen))
		goto out4;

	ret = 0;

out4:
	emv_pk_free(rpk);
out3:
	tlvdb_free(db);
out2:
	emv_pk_free(ipk);
out:
	emv_pk_free(pk);

	return ret;
}

static int test_emv_pki_sign_icc_cert(struct crypto_pk *icp, struct crypto_pk *icc_cp)
{
	int ret = 1;
	struct emv_pk *ipk = make_issuer_pk(icp);
	if (!ipk)
		return ret;

	struct emv_pk *icc_pk = make_icc_pk(icc_cp);
	if (!icc_pk)
		goto out;

	struct tlvdb *db = emv_pki_sign_icc_cert(icp, icc_pk, sdad, sizeof(sdad));
	if (!db)
		goto out2;
	tlvdb_add(db, tlvdb_fixed(0x5a, 10, icc_pk->pan));

	struct emv_pk *rpk = emv_pki_recover_icc_cert(ipk, db, sdad, sizeof(sdad));
	if (!rpk)
		goto out3;

	if (memcmp(rpk->rid, icc_pk->rid, 5) ||
	    rpk->index != icc_pk->index ||
	    rpk->hash_algo != icc_pk->hash_algo ||
	    rpk->pk_algo != icc_pk->pk_algo ||
	    rpk->expire != icc_pk->expire ||
	    memcmp(rpk->serial, icc_pk->serial, 3) ||
	    memcmp(rpk->pan, icc_pk->pan, 10) ||
	    rpk->mlen != icc_pk->mlen ||
	    memcmp(rpk->modulus, icc_pk->modulus, rpk->mlen) ||
	    rpk->elen != icc_pk->elen ||
	    memcmp(rpk->exp, icc_pk->exp, rpk->elen))
		goto out4;

	ret = 0;

out4:
	emv_pk_free(rpk);
out3:
	tlvdb_free(db);
out2:
	emv_pk_free(icc_pk);
out:
	emv_pk_free(ipk);

	return ret;
}

static int test_emv_pki_sign_icc_pe_cert(struct crypto_pk *icp, struct crypto_pk *icc_pe_cp)
{
	int ret = 1;
	struct emv_pk *ipk = make_issuer_pk(icp);
	if (!ipk)
		return ret;

	struct emv_pk *icc_pe_pk = make_icc_pk(icc_pe_cp);
	if (!icc_pe_pk)
		goto out;

	struct tlvdb *db = emv_pki_sign_icc_pe_cert(icp, icc_pe_pk);
	if (!db)
		goto out2;
	tlvdb_add(db, tlvdb_fixed(0x5a, 10, icc_pe_pk->pan));

	struct emv_pk *rpk = emv_pki_recover_icc_pe_cert(ipk, db);
	if (!rpk)
		goto out3;

	if (memcmp(rpk->rid, icc_pe_pk->rid, 5) ||
	    rpk->index != icc_pe_pk->index ||
	    rpk->hash_algo != icc_pe_pk->hash_algo ||
	    rpk->pk_algo != icc_pe_pk->pk_algo ||
	    rpk->expire != icc_pe_pk->expire ||
	    memcmp(rpk->serial, icc_pe_pk->serial, 3) ||
	    memcmp(rpk->pan, icc_pe_pk->pan, 10) ||
	    rpk->mlen != icc_pe_pk->mlen ||
	    memcmp(rpk->modulus, icc_pe_pk->modulus, rpk->mlen) ||
	    rpk->elen != icc_pe_pk->elen ||
	    memcmp(rpk->exp, icc_pe_pk->exp, rpk->elen))
		goto out4;

	ret = 0;

out4:
	emv_pk_free(rpk);
out3:
	tlvdb_free(db);
out2:
	emv_pk_free(icc_pe_pk);
out:
	emv_pk_free(ipk);

	return ret;
}

static int test_emv_pki_sign_dac(struct crypto_pk *icp)
{
	int ret = 1;
	struct emv_pk *ipk = make_issuer_pk(icp);
	if (!ipk)
		return ret;

	struct tlvdb *db = emv_pki_sign_dac(icp, dac, sdad, sizeof(sdad));
	if (!db)
		goto out;

	struct tlvdb *rdb = emv_pki_recover_dac(ipk, db, sdad, sizeof(sdad));
	if (!rdb)
		goto out2;

	const struct tlv *dac_tlv = tlvdb_get(rdb, 0x9f45, NULL);
	if (!dac_tlv || dac_tlv->len != sizeof(dac) || memcmp(dac_tlv->value, dac, sizeof(dac)))
		goto out3;

	ret = 0;

out3:
	tlvdb_free(rdb);
out2:
	tlvdb_free(db);
out:
	emv_pk_free(ipk);

	return ret;
}

static int test_emv_pki_sign_idn(struct crypto_pk *icc_cp)
{
	int ret = 1;
	struct emv_pk *icc_pk = make_issuer_pk(icc_cp);
	if (!icc_pk)
		return ret;

	struct tlvdb *db = emv_pki_sign_idn(icc_cp, idn, sizeof(idn), dd1, sizeof(dd1));
	if (!db)
		goto out;

	struct tlvdb *rdb = emv_pki_recover_idn(icc_pk, db, dd1, sizeof(dd1));
	if (!rdb)
		goto out2;

	const struct tlv *idn_tlv = tlvdb_get(rdb, 0x9f4c, NULL);
	if (!idn_tlv || idn_tlv->len != sizeof(idn) || memcmp(idn_tlv->value, idn, sizeof(idn)))
		goto out3;

	ret = 0;

out3:
	tlvdb_free(rdb);
out2:
	tlvdb_free(db);
out:
	emv_pk_free(icc_pk);

	return ret;
}

int main(void)
{

	unsigned int keylength = 1024;

	printf("Testing key length %u\n", keylength);

	struct crypto_pk *cp = crypto_pk_genkey(PK_RSA, 1, keylength, 3);
	if (!cp) {
		printf("Key generation failed\n");

		return 1;
	}

	if (test_emv_pki_make_ca(cp)) {
		printf("Failed emv_pki_make_ca test\n");
		crypto_pk_close(cp);

		return 1;
	}

	if (test_emv_pki_sign_issuer_cert(cp, cp)) {
		printf("Failed emv_pki_sign_issuer_cert test\n");
		crypto_pk_close(cp);

		return 1;
	}

	if (test_emv_pki_sign_icc_cert(cp, cp)) {
		printf("Failed emv_pki_sign_icc_cert test\n");
		crypto_pk_close(cp);

		return 1;
	}

	if (test_emv_pki_sign_icc_pe_cert(cp, cp)) {
		printf("Failed emv_pki_sign_icc_pe_cert test\n");
		crypto_pk_close(cp);

		return 1;
	}

	if (test_emv_pki_sign_dac(cp)) {
		printf("Failed emv_pki_sign_dac test\n");
		crypto_pk_close(cp);

		return 1;
	}

	if (test_emv_pki_sign_idn(cp)) {
		printf("Failed emv_pki_sign_idn test\n");
		crypto_pk_close(cp);

		return 1;
	}

	crypto_pk_close(cp);

	return 0;
}
