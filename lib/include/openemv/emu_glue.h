#ifndef EMU_GLUE_H
#define EMU_GLUE_H

#include <stdint.h>
struct emu_card;

struct emu_card *emu_card_parse(const char *fname);
void emu_card_free(struct emu_card *card);

uint16_t emu_command(struct emu_card *card, uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, size_t lc, const unsigned char *data, const unsigned char **ret, size_t *ret_len);

#endif
