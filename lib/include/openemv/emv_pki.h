#ifndef EMV_PKI_H
#define EMV_PKI_H

#include "openemv/capk.h"
#include "openemv/tlv.h"

#include <stddef.h>

struct capk *emv_pki_recover_issuer_cert(const struct capk *pk, struct tlvdb *db);
struct capk *emv_pki_recover_icc_cert(const struct capk *pk, struct tlvdb *db, unsigned char *sda_data, size_t sda_data_len);
struct capk *emv_pki_recover_icc_pe_cert(const struct capk *pk, struct tlvdb *db);

struct tlvdb *emv_pki_recover_dac(const struct capk *pk, const struct tlvdb *db, unsigned char *sda_data, size_t sda_data_len);
struct tlvdb *emv_pki_recover_idn(const struct capk *pk, const struct tlvdb *db, unsigned char *dyn_data, size_t dyn_data_len);
struct tlvdb *emv_pki_perform_cda(const struct capk *enc_pk, const struct tlvdb *db,
		const struct tlvdb *this_db,
		unsigned char *pdol_data, size_t pdol_data_len,
		unsigned char *crm1_data, size_t crm1_data_len,
		unsigned char *crm2_data, size_t crm2_data_len);

#endif
