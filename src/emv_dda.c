#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "scard.h"
#include "sc_helpers.h"
#include "tlv.h"
#include "emv_tags.h"
#include "capk.h"
#include "crypto_backend.h"
#include "dol.h"
#include "emv_pki.h"

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
		printf("%s\n", scard_error(sc));
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
	return docmd(sc, 0x80, 0xca, tag >> 8, tag & 0xff, 0, NULL);
}

static const unsigned char default_ddol_value[] = {0x9f, 0x37, 0x04};
static struct tlv default_ddol_tlv = {.tag = 0x499f, .len = 3, .value = default_ddol_value };

static struct tlvdb *perform_dda(const struct capk *pk, const struct tlvdb *db, struct sc *sc)
{
	const struct tlv *e;
	const struct tlv *ddol_tlv = tlvdb_get(db, 0x9f49, NULL);

	if (!pk)
		return NULL;

	if (!ddol_tlv)
		ddol_tlv = &default_ddol_tlv;

	size_t ddol_data_len;
	unsigned char *ddol_data = dol_process(ddol_tlv, db, &ddol_data_len);
	if (!ddol_data)
		return NULL;

	struct tlvdb *dda_db = docmd(sc, 0x00, 0x88, 0x00, 0x00, ddol_data_len, ddol_data);
	if (!dda_db) {
		free(ddol_data);
		return NULL;
	}

	if ((e = tlvdb_get(dda_db, 0x80, NULL)) != NULL) {
		struct tlvdb *t;
		t = tlvdb_fixed(0x4b9f, e->len, e->value);
		tlvdb_free(dda_db);
		dda_db = t;
	}

	struct tlvdb *idn_db = emv_pki_recover_idn(pk, dda_db, ddol_data, ddol_data_len);
	free(ddol_data);
	if (!idn_db) {
		tlvdb_free(dda_db);
		return NULL;
	}

	tlvdb_add(dda_db, idn_db);

	return dda_db;
}

static struct capk *get_ca_pk(struct tlvdb *db)
{
	const struct tlv *df_tlv = tlvdb_get(db, 0x84, NULL);
	const struct tlv *caidx_tlv = tlvdb_get(db, 0x8f, NULL);

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
		printf("Verifying CA PK for %02hhx:%02hhx:%02hhx:%02hhx:%02hhx IDX %02hhx %zd bits...",
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
		printf("%s\n", scard_error(sc));
		return 1;
	}

	scard_connect(sc, 0);
	if (scard_is_error(sc)) {
		printf("%s\n", scard_error(sc));
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
		const unsigned char gpo_dol_value[] = {
			0x82, 0x02, /* AIP */
			0x94, 0x00, /* AFL */
		};
		const struct tlv gpo_dol = {0x0, sizeof(gpo_dol_value), gpo_dol_value};
		struct tlvdb *gpo_db = dol_parse(&gpo_dol, e->value, e->len);
		tlvdb_add(s, t);
		t = gpo_db;
	}
	tlvdb_add(s, t);

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
	const struct tlv *sdatl_tlv = tlvdb_get(s, 0x9f4a, NULL);
	if (sdatl_tlv) {
		const struct tlv *aip_tlv = tlvdb_get(s, 0x82, NULL);
		if (sdatl_tlv->len == 1 && sdatl_tlv->value[0] == 0x82 && aip_tlv) {
			sda_data = realloc(sda_data, sda_len + aip_tlv->len);
			memcpy(sda_data + sda_len, aip_tlv->value, aip_tlv->len);
			sda_len += aip_tlv->len;
		} else {
			/* Error!! */
			free(sda_data);
			sda_data = NULL;
			sda_len = 0;
		}
	}


	struct capk *pk = get_ca_pk(s);
	struct capk *issuer_pk = emv_pki_recover_issuer_cert(pk, s);
	if (issuer_pk)
		printf("Issuer PK recovered!\n");
	struct capk *icc_pk = emv_pki_recover_icc_cert(issuer_pk, s, sda_data, sda_len);
	if (icc_pk)
		printf("ICC PK recovered!\n");
	struct tlvdb *dac_db = emv_pki_recover_dac(issuer_pk, s, sda_data, sda_len);
	if (dac_db) {
		const struct tlv *dac_tlv = tlvdb_get(dac_db, 0x9f45, NULL);
		printf("SDA verified OK (%02hhx:%02hhx)!\n", dac_tlv->value[0], dac_tlv->value[1]);
		tlvdb_add(s, dac_db);
	}
	struct tlvdb *idn_db = perform_dda(icc_pk, s, sc);
	if (idn_db) {
		const struct tlv *idn_tlv = tlvdb_get(idn_db, 0x9f4c, NULL);
		printf("DDA verified OK (IDN %zd bytes long)!\n", idn_tlv->len);
		tlvdb_add(s, idn_db);
	}
	capk_free(pk);
	capk_free(issuer_pk);
	capk_free(icc_pk);

	free(sda_data);

	tlvdb_add(s, get_data(sc, 0x9f36));
	tlvdb_add(s, get_data(sc, 0x9f13));
	tlvdb_add(s, get_data(sc, 0x9f17));
	tlvdb_add(s, get_data(sc, 0x9f4f));

	printf("Final\n");
	tlvdb_visit(s, print_cb, NULL);
	tlvdb_free(s);

	scard_disconnect(sc);
	if (scard_is_error(sc)) {
		printf("%s\n", scard_error(sc));
		return 1;
	}
	scard_shutdown(&sc);
	if (scard_is_error(sc)) {
		printf("%s\n", scard_error(sc));
		return 1;
	}

	return 0;
}
