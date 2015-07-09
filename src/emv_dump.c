#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "openemv/scard.h"
#include "openemv/sc_helpers.h"
#include "openemv/tlv.h"
#include "openemv/emv_tags.h"
#include "openemv/dol.h"
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

static struct tlvdb *get_data(struct sc *sc, tlv_tag_t tag)
{
	return docmd(sc, 0x80, 0xca, tag >> 8, tag & 0xff, 0, NULL);
}

const struct {
	size_t name_len;
	const unsigned char name[16];
} apps[] = {
	{ 7, {0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, }},
	{ 7, {0xa0, 0x00, 0x00, 0x00, 0x03, 0x20, 0x10, }},
	{ 7, {0xa0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10, }},
	{ 0, {}},
};

int main(void)
{
	int i;
	struct sc *sc;

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
	for (i = 0, s = NULL; apps[i].name_len != 0; i++) {
		s = docmd(sc, 0x00, 0xa4, 0x04, 0x00, apps[i].name_len, apps[i].name);
		if (s)
			break;
	}
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
	for (i = 0; i < e->len; i += 4) {
		unsigned char p2 = e->value[i + 0];
		unsigned char first = e->value[i + 1];
		unsigned char last = e->value[i + 2];
//		unsigned char sdarec = e->value[i + 3];

		if (p2 == 0 || p2 == (31 << 3) || first == 0 || first > last)
			break; /* error */

		for (; first <= last; first ++) {
			t = docmd(sc, 0x00, 0xb2, first, p2 | 0x04, 0, NULL);
			if (!t)
				return 1;
			tlvdb_add(s, t);
		}

	}

	/* Generate AC asking for AAC */
	size_t crm_data_len;
	unsigned char *crm_data = dol_process(tlvdb_get(s, 0x8c, NULL), s, &crm_data_len);
	t = docmd(sc, 0x80, 0xae, 0x00, 0x00, crm_data_len, crm_data);
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
	tlvdb_add(s, t);
	free(crm_data);

	tlvdb_add(s, get_data(sc, 0x9f36));
	tlvdb_add(s, get_data(sc, 0x9f13));
	tlvdb_add(s, get_data(sc, 0x9f17));
	tlvdb_add(s, get_data(sc, 0x9f4f));

	tlvdb_visit(s, print_cb, NULL);

	const struct tlv *logent_tlv = tlvdb_get(s, 0x9f4d, NULL);
	const struct tlv *logent_dol = tlvdb_get(s, 0x9f4f, NULL);
	if (logent_tlv && logent_tlv->len == 2 && logent_dol) {
		for (i = 1; i <= logent_tlv->value[1]; i++) {
			unsigned short sw;
			size_t log_len;
			unsigned char *log = sc_command(sc, 0x00, 0xb2, i, (logent_tlv->value[0] << 3) | 0x4, 0, NULL, &sw, &log_len);
			if (!log)
				continue;

			if (sw == 0x9000) {
				printf("Log #%d\n", i);
				struct tlvdb *log_db = dol_parse(logent_dol, log, log_len);
				tlvdb_visit(log_db, print_cb, NULL);
				tlvdb_free(log_db);
			}
			free(log);
		}
	}

	tlvdb_free(s);

	scard_disconnect(sc);
	if (scard_is_error(sc)) {
		printf("%s\n", scard_error(sc));
		return 1;
	}
	scard_shutdown(sc);

	return 0;
}
