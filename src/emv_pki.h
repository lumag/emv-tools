#ifndef EMV_PKI_H
#define EMV_PKI_H

#include "capk.h"
#include "tlv.h"

#include <stddef.h>

struct capk *emv_pki_recover_issuer_cert(const struct capk *pk, struct tlvdb *db);
struct capk *emv_pki_recover_icc_cert(const struct capk *pk, struct tlvdb *db, unsigned char *sda_data, size_t sda_data_len);
struct capk *emv_pki_recover_icc_pe_cert(const struct capk *pk, struct tlvdb *db);

#endif
