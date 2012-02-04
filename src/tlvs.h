#ifndef TLVS_H
#define TLVS_H

struct tlv;
struct tlv_elem_info;

struct tlvs;

struct tlvs *tlvs_new(void);
void tlvs_free(struct tlvs *tlvs);
void tlvs_add(struct tlvs *tlvs, struct tlv *tlv);
const struct tlv_elem_info *tlvs_get(struct tlvs *tlvs, uint16_t tag);
bool tlvs_visit(struct tlvs *tlv, bool (*cb)(void *data, const struct tlv_elem_info *tei), void *data);

#endif
