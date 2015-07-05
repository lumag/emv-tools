#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "openemv/scard.h"
#include "openemv/sc_helpers.h"
#include "openemv/tlv.h"
#include "openemv/emv_tags.h"
#include "openemv/emv_pk.h"
#include "openemv/crypto.h"
#include "openemv/dol.h"
#include "openemv/emv_pki.h"
#include "openemv/dump.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool print_cb(void *data, const struct tlv *tlv)
{
//	if (tlv_is_constructed(tlv)) return true;
	emv_tag_dump(tlv, stdout);
	dump_buffer(tlv->value, tlv->len, stdout);
	return true;
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

	outbuf = sc_command(sc, cla, ins, p1, p2, dlen, data, &sw, &outlen);
	if (!outbuf)
		return NULL;

	if (sw == 0x9000)
		tlvdb = tlvdb_parse(outbuf, outlen);

	free(outbuf);

	return tlvdb;
}

static struct emv_pk *get_ca_pk(struct tlvdb *db)
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
		struct emv_pk *pk = emv_pk_parse_pk(buf);
		if (!pk)
			continue;
		if (memcmp(pk->rid, df_tlv->value, 5) || pk->index != caidx_tlv->value[0]) {
			emv_pk_free(pk);
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
		if (emv_pk_verify(pk)) {
			printf("OK\n");
			fclose(f);

			return pk;
		}

		printf("Failed!\n");
		emv_pk_free(pk);
		fclose(f);

		return NULL;
	}

	fclose(f);

	return NULL;
}

int main(void)
{
	struct sc *sc;
	unsigned char cmd4[] = {
		0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10,
	};

	if (!crypto_be_init())
		exit(2);

	sc = scard_init("pcsc");
	if (!sc) {
		printf("Cannot init scard\n");
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

	struct tlv pdol_data_tlv;
	size_t pdol_data_len;
	unsigned char *pdol_data;

	pdol_data_tlv.tag = 0x83;
	pdol_data_tlv.value = dol_process(tlvdb_get(s, 0x9f38, NULL), s, &pdol_data_tlv.len);
	pdol_data = tlv_encode(&pdol_data_tlv, &pdol_data_len);
	if (!pdol_data)
		return 1;
	free((unsigned char *)pdol_data_tlv.value);

	t = docmd(sc, 0x80, 0xa8, 0x00, 0x00, pdol_data_len, pdol_data);
	free(pdol_data);
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
			unsigned short sw;
			size_t outlen;
			unsigned char *outbuf;

			outbuf = sc_command(sc, 0x00, 0xb2, first, p2 | 0x04, 0, NULL, &sw, &outlen);
			if (!outbuf)
				return 1;

			if (sw == 0x9000) {
				t = tlvdb_parse(outbuf, outlen);
				if (!t)
					return 1;
			} else
				return 1;

			if (sdarec) {
				const unsigned char *data;
				size_t data_len;

				if (p2 < (11 << 3)) {
					const struct tlv *e = tlvdb_get(t, 0x70, NULL);
					if (!e)
						return 1;

					data = e->value;
					data_len = e->len;
				} else {
					data = outbuf;
					data_len = outlen;
				}

				sda_data = realloc(sda_data, sda_len + data_len);
				memcpy(sda_data + sda_len, data, data_len);
				sda_len += data_len;
				sdarec --;
			}

			free(outbuf);
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


	struct emv_pk *pk = get_ca_pk(s);
	struct emv_pk *issuer_pk = emv_pki_recover_issuer_cert(pk, s);
	if (issuer_pk)
		printf("Issuer PK recovered!\n");
	struct emv_pk *icc_pk = emv_pki_recover_icc_cert(issuer_pk, s, sda_data, sda_len);
	if (icc_pk)
		printf("ICC PK recovered!\n");
	struct tlvdb *dac_db = emv_pki_recover_dac(issuer_pk, s, sda_data, sda_len);
	if (dac_db) {
		const struct tlv *dac_tlv = tlvdb_get(dac_db, 0x9f45, NULL);
		printf("SDA verified OK (%02hhx:%02hhx)!\n", dac_tlv->value[0], dac_tlv->value[1]);
		tlvdb_add(s, dac_db);
	}

#define TAG(tag, len, value...) tlvdb_add(s, tlvdb_fixed(tag, len, (unsigned char[]){value}))
	TAG(0x029f, 6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
	TAG(0x1a9f, 2, 0x06, 0x43);
	TAG(0x95, 5, 0x00, 0x00, 0x00, 0x00, 0x00);
	TAG(0x2a5f, 2, 0x06, 0x43);
	TAG(0x9a, 3, 0x14, 0x09, 0x25);
	TAG(0x9c, 1, 0x50);
	TAG(0x379f, 4, 0x12, 0x34, 0x57, 0x79);
	TAG(0x359f, 2, 0x23);
	TAG(0x349f, 3, 0x1e, 0x03, 0x00);
#undef TAG

	/* Generate AC asking for TC/CDA, then check CDA */
	size_t crm_data_len;
	unsigned char *crm_data = dol_process(tlvdb_get(s, 0x8c, NULL), s, &crm_data_len);
	dump_buffer(crm_data, crm_data_len, stdout);
	t = docmd(sc, 0x80, 0xae, 0x50, 0x00, crm_data_len, crm_data);
	if ((e = tlvdb_get(t, 0x80, NULL)) != NULL) {
		/* CID, ATC, AC, IAD */
		const unsigned char ac_dol_value[] = {
			0x9f, 0x27, 0x01, /* CID */
			0x9f, 0x36, 0x02, /* ATC */
			0x9f, 0x26, 0x08, /* AC */
			0x9f, 0x10, 0x00, /* IAD */
		};
		const struct tlv ac_dol = {0x0, sizeof(ac_dol_value), ac_dol_value};
		struct tlvdb *ac_db = dol_parse(&ac_dol, e->value, e->len);
		tlvdb_add(s, t);
		t = ac_db;
	}
	struct tlvdb *idn_db = emv_pki_perform_cda(icc_pk, s, t,
			NULL, 0,
			crm_data, crm_data_len,
			NULL, 0);
	tlvdb_add(s, t);
	if (idn_db) {
		const struct tlv *idn_tlv = tlvdb_get(idn_db, 0x9f4c, NULL);
		printf("CDA verified OK (IDN %zd bytes long)!\n", idn_tlv->len);
		tlvdb_add(s, idn_db);
	}

	free(crm_data);
	emv_pk_free(pk);
	emv_pk_free(issuer_pk);
	emv_pk_free(icc_pk);

	free(sda_data);

	printf("Final\n");
	tlvdb_visit(s, print_cb, NULL);
	tlvdb_free(s);

	scard_disconnect(sc);
	if (scard_is_error(sc)) {
		printf("%s\n", scard_error(sc));
		return 1;
	}
	scard_shutdown(sc);

	return 0;
}
