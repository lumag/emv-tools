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

#include "openemv/scard.h"
#include "openemv/sc_helpers.h"
#include "openemv/tlv.h"
#include "openemv/emv_tags.h"
#include "openemv/emv_pk.h"
#include "openemv/crypto.h"
#include "openemv/dol.h"
#include "openemv/emv_pki.h"
#include "openemv/dump.h"
#include "openemv/config.h"
#include "openemv/emv_commands.h"

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

static struct emv_pk *get_ca_pk(struct tlvdb *db)
{
	const struct tlv *df_tlv = tlvdb_get(db, 0x84, NULL);
	const struct tlv *caidx_tlv = tlvdb_get(db, 0x8f, NULL);

	if (!df_tlv || !caidx_tlv || df_tlv->len < 6 || caidx_tlv->len != 1)
		return NULL;

	return emv_pk_get_ca_pk(df_tlv->value, caidx_tlv->value[0]);
}

const struct {
	size_t name_len;
	const unsigned char name[16];
} apps[] = {
	{ 7, {0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, }},
	{ 7, {0xa0, 0x00, 0x00, 0x00, 0x03, 0x20, 0x10, }},
	{ 7, {0xa0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10, }},
	{ 7, {0xa0, 0x00, 0x00, 0x00, 0x04, 0x30, 0x60, }},
	{ 0, {}},
};

int main(void)
{
	int i;
	struct sc *sc;

	sc = scard_init(NULL);
	if (!sc) {
		printf("Cannot init scard\n");
		return 1;
	}

	scard_connect(sc, 1);
	if (scard_is_error(sc)) {
		printf("%s\n", scard_error(sc));
		return 1;
	}

	struct tlvdb *s;
	struct tlvdb *t;
	for (i = 0, s = NULL; apps[i].name_len != 0; i++) {
		s = emv_select(sc, apps[i].name, apps[i].name_len);
		if (s)
			break;
	}
	if (!s)
		return 1;

	size_t pdol_data_len;
	unsigned char *pdol_data = dol_process(tlvdb_get(s, 0x9f38, NULL), s, &pdol_data_len);
	struct tlv pdol_data_tlv = { .tag = 0x83, .len = pdol_data_len, .value = pdol_data };

	size_t pdol_data_tlv_data_len;
	unsigned char *pdol_data_tlv_data = tlv_encode(&pdol_data_tlv, &pdol_data_tlv_data_len);
	if (!pdol_data_tlv_data)
		return 1;

	t = emv_gpo(sc, pdol_data_tlv_data, pdol_data_tlv_data_len);
	free(pdol_data_tlv_data);
	if (!t)
		return 1;
	tlvdb_add(s, t);

	unsigned char *sda_data = NULL;
	size_t sda_len = 0;
	bool ok = emv_read_records(sc, s, &sda_data, &sda_len);
	if (!ok)
		return 1;

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
	TAG(0x9f02, 6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
	TAG(0x9f1a, 2, 0x06, 0x43);
	TAG(0x95, 5, 0x00, 0x00, 0x00, 0x00, 0x00);
	TAG(0x5f2a, 2, 0x06, 0x43);
	TAG(0x9a, 3, 0x14, 0x09, 0x25);
	TAG(0x9c, 1, 0x50);
	TAG(0x9f37, 4, 0x12, 0x34, 0x57, 0x79);
	TAG(0x9f35, 1, 0x23);
	TAG(0x9f34, 3, 0x1e, 0x03, 0x00);
#undef TAG

	/* Generate AC asking for TC/CDA, then check CDA */
	size_t crm_data_len;
	unsigned char *crm_data = dol_process(tlvdb_get(s, 0x8c, NULL), s, &crm_data_len);
	dump_buffer(crm_data, crm_data_len, stdout);
	t = emv_generate_ac(sc, 0x50, crm_data, crm_data_len);
	free(crm_data);
	if (!t)
		return 1;
	struct tlvdb *idn_db = emv_pki_perform_cda(icc_pk, s, t,
			pdol_data, pdol_data_len,
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
	free(pdol_data);

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
