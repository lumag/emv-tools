#ifndef EMU_GLUE_H
#define EMU_GLUE_H

struct emu_card;

struct emu_card *card_parse(const char *fname);
void card_free(struct emu_card *card);
const struct emu_df *card_get_df(const struct emu_card *card);

#endif
