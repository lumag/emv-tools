#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "scard.h"
#include "sc_helpers.h"
#include "tlv.h"
#include "emv_tags.h"
#include "capk.h"
#include "crypto_backend.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void dump(const unsigned char *ptr, size_t len)
{
	int i, j;

	for (i = 0; i < len; i += 16) {
		printf("\t%02x:", i);
		for (j = 0; j < 16; j++) {
			if (i + j < len)
				printf(" %02hhx", ptr[i + j]);
			else
				printf("   ");
		}
		printf(" |");
		for (j = 0; j < 16 && i + j < len; j++) {
			printf("%c", (ptr[i+j] >= 0x20 && ptr[i+j] < 0x7f) ? ptr[i+j] : '.' );
		}
		printf("\n");
	}
}

static bool print_cb(void *data, const struct tlv *tlv)
{
	if (tlv->tag & 0x20) return true;
	emv_tag_dump(tlv, stdout);
	dump(tlv->value, tlv->len);
	return true;
}

static unsigned char *docmd_int(struct sc *sc,
		unsigned char cla,
		unsigned char ins,
		unsigned char p1,
		unsigned char p2,
		size_t dlen,
		const unsigned char *data,
		unsigned short *sw,
		size_t *outlen)
{
	unsigned char *outbuf;

	printf("CMD: %02hhx %02hhx %02hhx %02hhx (%02zx)\n", cla, ins, p1, p2, dlen);
	outbuf = sc_command(sc, cla, ins, p1, p2,
			dlen, data, sw, outlen);
	if (scard_is_error(sc)) {
		printf(scard_error(sc));
		return NULL;
	}
	printf("response (%hx)\n", *sw);

	return outbuf;
}

static struct tlvdb *docmd(struct sc *sc,
		unsigned char cla,
		unsigned char ins,
		unsigned char p1,
		unsigned char p2,
		size_t dlen,
		const unsigned char *data)
{
	unsigned short sw;
	size_t outlen;
	unsigned char *outbuf;
	struct tlvdb *tlvdb = NULL;

	outbuf = docmd_int(sc, cla, ins, p1, p2, dlen, data, &sw, &outlen);

	if (sw == 0x9000) {
		tlvdb = tlvdb_parse(outbuf, outlen);
	}

	free(outbuf);

	return tlvdb;
}

static struct tlvdb *get_data(struct sc *sc, tlv_tag_t tag)
{
	return docmd(sc, 0x80, 0xca, tag & 0xff, tag >> 8, 0, NULL);
}

static struct tlv empty_issuer_rem_tlv = {.tag = 0x92, .len = 0, .value = NULL};

static struct capk *recover_issuer_cert(const struct capk *pk, struct tlvdb *db)
{
	struct crypto_pk *kcp;
	unsigned char *issuer_data;
	size_t issuer_data_len;
	size_t issuer_pk_len;

	struct tlv *issuer_cert_tlv = tlvdb_get(db, 0x90, NULL);
	struct tlv *issuer_rem_tlv = tlvdb_get(db, 0x92, NULL);
	struct tlv *issuer_exp_tlv = tlvdb_get(db, 0x329f, NULL);

	if (!pk)
		return NULL;

	if (!issuer_cert_tlv || !issuer_exp_tlv)
		return NULL;

	if (!issuer_rem_tlv)
		issuer_rem_tlv = &empty_issuer_rem_tlv;

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

	printf("Issuer PK recovered!\n");

	return issuer_pk;
}

static struct tlvdb *perform_sda(const struct capk *pk, struct tlvdb *db, unsigned char *sda_data, size_t sda_len)
{
	struct crypto_pk *ikcp;

	struct tlv *ssad_tlv = tlvdb_get(db, 0x93, NULL);

	if (!pk)
		return NULL;

	if (!ssad_tlv) {
		return NULL;
	};

	if (ssad_tlv->len != pk->mlen) {
		return NULL;
	}

	ikcp = crypto_pk_open(pk->pk_algo,
			pk->modulus, pk->mlen,
			pk->exp, pk->elen);
	if (!ikcp)
		return NULL;

	size_t ssad_len;
	unsigned char *ssad = crypto_pk_encrypt(ikcp, ssad_tlv->value, ssad_tlv->len, &ssad_len);
	crypto_pk_close(ikcp);

	if (ssad[ssad_len - 1] != 0xbc || ssad[0] != 0x6a || ssad[1] != 0x03) {
		free(ssad);
		return NULL;
	}

	struct crypto_hash *ch;
	ch = crypto_hash_open(pk->hash_algo);
	if (!ch) {
		free(ssad);
		return NULL;
	}

	crypto_hash_write(ch, ssad + 1, ssad_len - 22);
	crypto_hash_write(ch, sda_data, sda_len);

	struct tlv *sdatl_tlv = tlvdb_get(db, 0x4a9f, NULL);
	if (sdatl_tlv) {
		struct tlv *aip_tlv = tlvdb_get(db, 0x82, NULL);

		if (sdatl_tlv->len != 1 || sdatl_tlv->value[0] != 0x82 || !aip_tlv) {
			free(ssad);
			return NULL;
		}

		crypto_hash_write(ch, aip_tlv->value, aip_tlv->len);
	}

	if (memcmp(ssad + ssad_len - 21, crypto_hash_read(ch), 20)) {
		crypto_hash_close(ch);
		free(ssad);
		return NULL;
	}

	crypto_hash_close(ch);

	unsigned char dac[2];
	dac[0] = ssad[3];
	dac[1] = ssad[4];

	free(ssad);

	struct tlvdb *dac_db = tlvdb_fixed(0x459f, 2, dac);
	if (!dac_db)
		return NULL;

	printf("SDA verified OK (%02hx:%02hx)!\n", dac[0], dac[1]);
	return dac_db;
}

static struct capk *get_ca_pk(struct tlvdb *db)
{
	struct tlv *df_tlv = tlvdb_get(db, 0x84, NULL);
	struct tlv *caidx_tlv = tlvdb_get(db, 0x8f, NULL);

	if (!df_tlv || !caidx_tlv || df_tlv->len < 6 || caidx_tlv->len != 1)
		return NULL;

	FILE *f = fopen("capk.txt", "r");

	if (!f) {
		perror("fopen");
		return NULL;
	}

	while (!feof(f)) {
		char buf[BUFSIZ];
		if (fgets(buf, sizeof(buf), f) == NULL)
			break;
		struct capk *pk = capk_parse_pk(buf);
		if (!pk)
			continue;
		if (memcmp(pk->rid, df_tlv->value, 5) || pk->index != caidx_tlv->value[0]) {
			capk_free(pk);
			continue;
		}
		printf("Verifying CA PK for %02hhx:%02hhx:%02hhx:%02hhx:%02hhx IDX %02hhx %d bits...",
				pk->rid[0],
				pk->rid[1],
				pk->rid[2],
				pk->rid[3],
				pk->rid[4],
				pk->index,
				pk->mlen * 8);
		if (capk_verify(pk)) {
			printf("OK\n");
			return pk;
		}

		printf("Failed!\n");
		capk_free(pk);
		return NULL;
	}

	return NULL;
}

int main(void)
{
	struct sc *sc;
	unsigned char cmd4[] = {
		0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10,
	};
	unsigned char cmd5[] = {
		0x83, 0x00,
	};

	if (!crypto_be_init())
		exit(2);

	sc = scard_init();
	if (scard_is_error(sc)) {
		printf(scard_error(sc));
		return 1;
	}

	scard_connect(sc, 0);
	if (scard_is_error(sc)) {
		printf(scard_error(sc));
		return 1;
	}

	struct tlvdb *s;
	struct tlvdb *t;
	const struct tlv *e;
	s = docmd(sc, 0x00, 0xa4, 0x04, 0x00, sizeof(cmd4), cmd4);
	if (!s)
		return 1;
	t = docmd(sc, 0x80, 0xa8, 0x00, 0x00, sizeof(cmd5), cmd5);
	if (!t)
		return 1;
	if ((e = tlvdb_get(t, 0x80, NULL)) != NULL) {
		struct tlvdb *t1, *t2;
		t1 = tlvdb_fixed(0x82, 2, e->value);
		t2 = tlvdb_fixed(0x94, e->len - 2, e->value+2);
		tlvdb_add(s, t1);
		tlvdb_add(s, t2);
		tlvdb_free(t);
	} else {
		tlvdb_add(s, t);
	}

	tlvdb_add(s, get_data(sc, 0x369f));
	tlvdb_add(s, get_data(sc, 0x139f));
	tlvdb_add(s, get_data(sc, 0x179f));
	tlvdb_add(s, get_data(sc, 0x4f9f));

	e = tlvdb_get(s, 0x94, NULL);
	if (!e)
		return 1;
	int i;
	unsigned char *sda_data = NULL;
	size_t sda_len = 0;
	for (i = 0; i < e->len; i += 4) {
		unsigned char p2 = e->value[i + 0];
		unsigned char first = e->value[i + 1];
		unsigned char last = e->value[i + 2];
		unsigned char sdarec = e->value[i + 3];

		if (p2 == 0 || p2 == (31 << 3) || first == 0 || first > last)
			break; /* error */

		for (; first <= last; first ++) {
			if (p2 < (11 << 3)) {
				t = docmd(sc, 0x00, 0xb2, first, p2 | 0x04, 0, NULL);
				if (!t)
					return 1;
				if (sdarec) {
					const struct tlv *e = tlvdb_get(t, 0x70, NULL);
					if (!e)
						return 1;
					sda_data = realloc(sda_data, sda_len + e->len);
					memcpy(sda_data + sda_len, e->value, e->len);
					sda_len += e->len;
					sdarec --;
				}
			} else {
				unsigned short sw;
				size_t outlen;
				unsigned char *outbuf;
				outbuf = docmd_int(sc, 0x00, 0xb2, first, p2 | 0x04, 0, NULL, &sw, &outlen);

				if (sw == 0x9000) {
					t = tlvdb_parse(outbuf, outlen);
					if (!t)
						return 1;
				} else
					return 1;
				if (sdarec) {
					sda_data = realloc(sda_data, sda_len + outlen);
					memcpy(sda_data + sda_len, outbuf, outlen);
					sda_len += outlen;
					sdarec --;
				}

				free(outbuf);
			}
			tlvdb_add(s, t);
		}

	}

	struct capk *pk = get_ca_pk(s);
	struct capk *issuer_pk = recover_issuer_cert(pk, s);
	struct tlvdb *dac_db = perform_sda(issuer_pk, s, sda_data, sda_len);
	capk_free(pk);
	capk_free(issuer_pk);
	tlvdb_add(s, dac_db);

	free(sda_data);

	printf("Final\n");
	tlvdb_visit(s, print_cb, NULL);
	tlvdb_free(s);

	scard_disconnect(sc);
	if (scard_is_error(sc)) {
		printf(scard_error(sc));
		return 1;
	}
	scard_shutdown(&sc);
	if (scard_is_error(sc)) {
		printf(scard_error(sc));
		return 1;
	}

	return 0;
}
