/*
 * emv-tools - a set of tools to work with EMV family of smart cards
 * Copyright (C) 2012, 2015 Dmitry Eremin-Solenikov
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
#include "openemv/dol.h"
#include "openemv/emv_pki.h"
#include "openemv/dump.h"
#include "openemv/emv_commands.h"
#include "openemv/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool print_cb(void *data, const struct tlv *tlv)
{
	if (tlv_is_constructed(tlv)) return true;
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

static const unsigned char default_ddol_value[] = {0x9f, 0x37, 0x04};
static struct tlv default_ddol_tlv = {.tag = 0x9f49, .len = 3, .value = default_ddol_value };

static struct tlvdb *perform_dda(const struct emv_pk *pk, const struct tlvdb *db, struct sc *sc)
{
	const struct tlv *ddol_tlv = tlvdb_get(db, 0x9f49, NULL);

	if (!pk)
		return NULL;

	if (!ddol_tlv)
		ddol_tlv = &default_ddol_tlv;

	struct tlv *ddol_data_tlv = dol_process(ddol_tlv, db, 0);
	if (!ddol_data_tlv)
		return NULL;

	struct tlvdb *dda_db = emv_internal_authenticate(sc, ddol_data_tlv);
	if (!dda_db) {
		free(ddol_data_tlv);

		return NULL;
	}

	struct tlvdb *idn_db = emv_pki_recover_idn(pk, dda_db, ddol_data_tlv);
	free(ddol_data_tlv);
	if (!idn_db) {
		tlvdb_free(dda_db);
		return NULL;
	}

	tlvdb_add(dda_db, idn_db);

	return dda_db;
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

	scard_connect(sc, openemv_config_get_int("scard.reader", 0));
	if (scard_is_error(sc)) {
		printf("%s\n", scard_error(sc));
		return 1;
	}

	struct tlvdb *s;
	struct tlvdb *t;
	for (i = 0, s = NULL; apps[i].name_len != 0; i++) {
		const struct tlv aid_tlv = {
			.len = apps[i].name_len,
			.value = apps[i].name,
		};
		s = emv_select(sc, &aid_tlv);
		if (s)
			break;
	}
	if (!s)
		return 1;

	struct tlv *pdol_data_tlv = dol_process(tlvdb_get(s, 0x9f38, NULL), s, 0x83);
	if (!pdol_data_tlv)
		return 1;

	t = emv_gpo(sc, pdol_data_tlv);
	free(pdol_data_tlv);
	if (!t)
		return 1;
	tlvdb_add(s, t);

	struct tlv *sda_tlv = emv_read_records(sc, s);
	if (!sda_tlv)
		return 1;

	struct emv_pk *pk = get_ca_pk(s);
	struct emv_pk *issuer_pk = emv_pki_recover_issuer_cert(pk, s);
	if (issuer_pk)
		printf("Issuer PK recovered! RID %02hhx:%02hhx:%02hhx:%02hhx:%02hhx IDX %02hhx CSN %02hhx:%02hhx:%02hhx\n",
				issuer_pk->rid[0],
				issuer_pk->rid[1],
				issuer_pk->rid[2],
				issuer_pk->rid[3],
				issuer_pk->rid[4],
				issuer_pk->index,
				issuer_pk->serial[0],
				issuer_pk->serial[1],
				issuer_pk->serial[2]
				);
	struct emv_pk *icc_pk = emv_pki_recover_icc_cert(issuer_pk, s, sda_tlv);
	if (icc_pk)
		printf("ICC PK recovered! RID %02hhx:%02hhx:%02hhx:%02hhx:%02hhx IDX %02hhx CSN %02hhx:%02hhx:%02hhx\n",
				icc_pk->rid[0],
				icc_pk->rid[1],
				icc_pk->rid[2],
				icc_pk->rid[3],
				icc_pk->rid[4],
				icc_pk->index,
				icc_pk->serial[0],
				icc_pk->serial[1],
				icc_pk->serial[2]
				);
	struct emv_pk *icc_pe_pk = emv_pki_recover_icc_pe_cert(issuer_pk, s);
	if (icc_pe_pk)
		printf("ICC PE PK recovered! RID %02hhx:%02hhx:%02hhx:%02hhx:%02hhx IDX %02hhx CSN %02hhx:%02hhx:%02hhx\n",
				icc_pe_pk->rid[0],
				icc_pe_pk->rid[1],
				icc_pe_pk->rid[2],
				icc_pe_pk->rid[3],
				icc_pe_pk->rid[4],
				icc_pe_pk->index,
				icc_pe_pk->serial[0],
				icc_pe_pk->serial[1],
				icc_pe_pk->serial[2]
				);
	struct tlvdb *dac_db = emv_pki_recover_dac(issuer_pk, s, sda_tlv);
	if (dac_db) {
		const struct tlv *dac_tlv = tlvdb_get(dac_db, 0x9f45, NULL);
		printf("SDA verified OK (%02hhx:%02hhx)!\n", dac_tlv->value[0], dac_tlv->value[1]);
		tlvdb_add(s, dac_db);
	}
	struct tlvdb *idn_db = perform_dda(icc_pk, s, sc);
	if (idn_db) {
		const struct tlv *idn_tlv = tlvdb_get(idn_db, 0x9f4c, NULL);
		printf("DDA verified OK (IDN %zu bytes long)!\n", idn_tlv->len);
		tlvdb_add(s, idn_db);
	}


	/* Generate AC asking for AAC */
	struct tlv *crm_tlv = dol_process(tlvdb_get(s, 0x8c, NULL), s, 0);
	if (!crm_tlv)
		return 1;
	t = emv_generate_ac(sc, 0x00, crm_tlv);
	free(crm_tlv);
	tlvdb_add(s, t);

	tlvdb_add(s, emv_get_data(sc, 0x9f36));
	tlvdb_add(s, emv_get_data(sc, 0x9f13));
	tlvdb_add(s, emv_get_data(sc, 0x9f17));
	tlvdb_add(s, emv_get_data(sc, 0x9f4f));

	emv_pk_free(pk);
	emv_pk_free(issuer_pk);
	emv_pk_free(icc_pk);
	emv_pk_free(icc_pe_pk);

	free(sda_tlv);

	tlvdb_visit(s, print_cb, NULL);

	const struct tlv *logent_tlv = tlvdb_get(s, 0x9f4d, NULL);
	const struct tlv *logent_dol = tlvdb_get(s, 0x9f4f, NULL);
	if (logent_tlv && logent_tlv->len == 2 && logent_dol) {
		for (i = 1; i <= logent_tlv->value[1]; i++) {
			unsigned short sw;
			size_t log_len;
			unsigned char *log = emv_read_record(sc, logent_tlv->value[0], i, &sw, &log_len);
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
