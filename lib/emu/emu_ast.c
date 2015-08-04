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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "openemv/emu_ast.h"
#include "openemv/dump.h"

#include <stdlib.h>
#include <string.h>

struct emu_value {
	struct emu_value *next;

	size_t len;
	unsigned char value[];
};

struct emu_property {
	struct emu_property *next;

	char *name;
	struct emu_value *value;
};

struct emu_df {
	struct emu_df *next;

	struct emu_property *property;
};

struct emu_fs {
	struct emu_df *df;
};

static unsigned char hexdigit(char c)
{
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	return c - '0';
}

struct emu_value *emu_value_new(const char *buf)
{
	size_t i, len;
	struct emu_value *v;

	len = strlen(buf) / 2;

	v = malloc(sizeof(*v) + len);
	v->len = len;
	v->next = NULL;

	for (i = 0; i < len; i++)
		v->value[i] = (hexdigit(buf[2*i]) << 4) | hexdigit(buf[2*i+1]);

	return v;
}

static struct emu_value *emu_value_append_int(struct emu_value *value, struct emu_value *add)
{
	struct emu_value *p = value;

	if (!p)
		return add;

	while (p->next)
		p = p->next;

	p->next = add;

	return value;
}

struct emu_value *emu_value_append(struct emu_value *value, const char *buf)
{
	return emu_value_append_int(value, emu_value_new(buf));
}

struct emu_value *emu_value_new_buf(const unsigned char *buf, size_t len)
{
	struct emu_value *v;

	v = malloc(sizeof(*v) + len);
	v->len = len;
	v->next = NULL;

	memcpy(v->value, buf, len);

	return v;
}

struct emu_value *emu_value_append_buf(struct emu_value *value, const unsigned char *buf, size_t len)
{
	return emu_value_append_int(value, emu_value_new_buf(buf, len));
}

void emu_value_free(struct emu_value *value)
{
	while (value) {
		struct emu_value *next = value->next;

		free(value);

		value = next;
	}
}

static void emu_dump_buffer(const unsigned char *value, size_t len, FILE *f)
{
	size_t k;

	for (k = 0; k < len; k += 16) {
		dump_buffer_simple(value + k,
				k + 16 < len ? 16 : len - k,
				f);
		if (k + 16 < len)
			fprintf(f, "\n\t\t ");
	}
}

void emu_value_dump(const struct emu_value *value, FILE *f)
{
	if (!value)
		return;

	fprintf(f, "<");
	while (value->next) {
		emu_dump_buffer(value->value, value->len, f);
		fprintf(f, ">,\n\t\t<");
		value = value->next;
	}

	emu_dump_buffer(value->value, value->len, f);
	fprintf(f, ">");
}

const unsigned char *emu_value_get(const struct emu_value *value, unsigned n, size_t *plen)
{
	const struct emu_value *current;

	for (current = value; --n && current; current = current->next)
		;

	if (!current) {
		*plen = 0;

		return NULL;
	}

	*plen = current->len;

	return current->value;
}

struct emu_property *emu_property_new(const char *name, struct emu_value *value)
{
	struct emu_property *property = malloc(sizeof(*property));

	property->next = NULL;
	property->name = strdup(name);
	property->value = value;

	return property;
}

void emu_property_dump(const struct emu_property *property, FILE *f)
{
	if (!property)
		return;

	fprintf(f, "%-5s = ", property->name);
	emu_value_dump(property->value, f);
}

void emu_property_free(struct emu_property *property)
{
	while (property) {
		struct emu_property *next = property->next;

		free(property->name);
		emu_value_free(property->value);
		free(property);

		property = next;
	}
}

const struct emu_value *emu_property_get_value(const struct emu_property *property)
{
	if (!property)
		return NULL;

	return property->value;
}

struct emu_df *emu_df_new(void)
{
	struct emu_df *df = malloc(sizeof(*df));

	df->property = NULL;
	df->next = NULL;

	return df;
}

void emu_df_dump(const struct emu_df *df, FILE *f)
{
	struct emu_property *property;

	if (!df)
		return;

	fprintf(f, "{\n");
	for (property = df->property; property; property = property->next) {
		fprintf(f, "\t");
		emu_property_dump(property, f);
		fprintf(f, ";\n");
	}

	fprintf(f, "};\n");
}

void emu_df_free(struct emu_df *df)
{
	while (df) {
		struct emu_df *next = df->next;

		emu_property_free(df->property);
		free(df);

		df = next;
	}
}

struct emu_df *emu_df_append(struct emu_df *df, struct emu_property *property)
{
	struct emu_property *p = df->property;

	if (!p) {
		df->property = property;
		return df;
	}

	while (p->next)
		p = p->next;

	p->next = property;

	return df;
}

const struct emu_property *emu_df_get_property(const struct emu_df *df, const char *name)
{
	const struct emu_property *property;

	if (!df)
		return NULL;

	for (property = df->property; property; property = property->next)
		if (!strcmp(property->name, name))
			return property;

	return NULL;
}

struct emu_fs *emu_fs_new(void)
{
	struct emu_fs *fs = malloc(sizeof(*fs));

	fs->df = NULL;

	return fs;
}

void emu_fs_dump(const struct emu_fs *fs, FILE *f)
{
	struct emu_df *df;

	if (!fs)
		return;

	for (df = fs->df; df; df = df->next)
		emu_df_dump(df, f);
}

void emu_fs_free(struct emu_fs *fs)
{
	if (!fs)
		return;

	emu_df_free(fs->df);
	free(fs);
}

struct emu_fs *emu_fs_append(struct emu_fs *fs, struct emu_df *df)
{
	struct emu_df *p = fs->df;

	if (!p) {
		fs->df = df;
		return fs;
	}

	while (p->next)
		p = p->next;

	p->next = df;

	return fs;
}

const struct emu_df *emu_fs_get_df(const struct emu_fs *fs, const unsigned char *name, size_t len)
{
	struct emu_df *df;
	size_t buf_len;
	const unsigned char *buf;

	if (len == 0)
		return fs->df;

	for (df = fs->df; df; df = df->next) {
		buf = emu_df_get_value(df, "name", 1, &buf_len);

		if (len > buf_len)
			continue;

		if (memcmp(buf, name, len))
			continue;

		return df;
	}

	return NULL;
}
