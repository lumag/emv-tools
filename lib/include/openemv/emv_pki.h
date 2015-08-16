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

#ifndef EMV_PKI_H
#define EMV_PKI_H

#include "openemv/emv_pk.h"
#include "openemv/tlv.h"

#include <stddef.h>

struct emv_pk *emv_pki_recover_issuer_cert(const struct emv_pk *pk, struct tlvdb *db);
struct emv_pk *emv_pki_recover_icc_cert(const struct emv_pk *pk, struct tlvdb *db, const unsigned char *sda_data, size_t sda_data_len);
struct emv_pk *emv_pki_recover_icc_pe_cert(const struct emv_pk *pk, struct tlvdb *db);

struct tlvdb *emv_pki_recover_dac(const struct emv_pk *pk, const struct tlvdb *db, const unsigned char *sda_data, size_t sda_data_len);
struct tlvdb *emv_pki_recover_idn(const struct emv_pk *pk, const struct tlvdb *db, const unsigned char *dyn_data, size_t dyn_data_len);
struct tlvdb *emv_pki_perform_cda(const struct emv_pk *enc_pk, const struct tlvdb *db,
		const struct tlvdb *this_db,
		const unsigned char *pdol_data, size_t pdol_data_len,
		const unsigned char *crm1_data, size_t crm1_data_len,
		const unsigned char *crm2_data, size_t crm2_data_len);

#endif
