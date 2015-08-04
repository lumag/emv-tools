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

#ifndef EMU_AST_H
#define EMU_AST_H

#include <stdio.h>

struct emu_value;
struct emu_property;
struct emu_df;
struct emu_fs;

struct emu_value *emu_value_new(const char *buf);
struct emu_value *emu_value_new_buf(const unsigned char *buf, size_t len);
void emu_value_dump(const struct emu_value *value, FILE *f);
void emu_value_free(struct emu_value *value);
struct emu_value *emu_value_append(struct emu_value *value, const char *buf);
struct emu_value *emu_value_append_buf(struct emu_value *value, const unsigned char *buf, size_t len);
const unsigned char *emu_value_get(const struct emu_value *value, unsigned n, size_t *plen);

struct emu_property *emu_property_new(const char *name, struct emu_value *value);
void emu_property_dump(const struct emu_property *property, FILE *f);
void emu_property_free(struct emu_property *property);
const struct emu_value *emu_property_get_value(const struct emu_property *property);

struct emu_df *emu_df_new(void);
void emu_df_dump(const struct emu_df *df, FILE *f);
void emu_df_free(struct emu_df *df);
struct emu_df *emu_df_append(struct emu_df *df, struct emu_property *property);
const struct emu_property *emu_df_get_property(const struct emu_df *df, const char *name);

struct emu_fs *emu_fs_new(void);
void emu_fs_dump(const struct emu_fs *fs, FILE *f);
void emu_fs_free(struct emu_fs *fs);
struct emu_fs *emu_fs_append(struct emu_fs *fs, struct emu_df *df);
const struct emu_df *emu_fs_get_df(const struct emu_fs *fs, const unsigned char *name, size_t name_len);

struct emu_fs *emu_fs_parse(FILE *f, const char *fname);

static inline const unsigned char *emu_df_get_value(const struct emu_df *df, const char *name, unsigned n, size_t *plen)
{
	const struct emu_property *prop = emu_df_get_property(df, name);
	if (!prop) {
		*plen = 0;
		return NULL;
	}

	const struct emu_value *value = emu_property_get_value(prop);
	if (!value) {
		*plen = 0;
		return NULL;
	}

	const unsigned char *buf = emu_value_get(value, n, plen);

	return buf;
}

#endif
