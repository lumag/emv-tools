#ifndef TAGS_H
#define TAGS_H

#include "openemv/tlv.h"
#include <stdio.h>

bool emv_tag_dump(const struct tlv *tlv, FILE *f);

#endif
