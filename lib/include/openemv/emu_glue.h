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

#ifndef EMU_GLUE_H
#define EMU_GLUE_H

#include <stdint.h>
#include <stddef.h>

struct emu_card;

struct emu_card *emu_card_parse(const char *fname);
void emu_card_free(struct emu_card *card);

uint16_t emu_command(struct emu_card *card, uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, size_t lc, const unsigned char *data, const unsigned char **ret, size_t *ret_len);

#endif
