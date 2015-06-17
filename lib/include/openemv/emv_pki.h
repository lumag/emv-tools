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

#endif
