#ifndef DOL_H
#define DOL_H

#include "tlv.h"
#include <stddef.h>

unsigned char *dol_process(const struct tlv *tlv, const struct tlvdb *tlvdb, size_t *len);
struct tlvdb *dol_parse(const struct tlv *tlv, const unsigned char *buf, size_t len);

#endif
