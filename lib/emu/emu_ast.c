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
	struct emu_property *props;
};

static unsigned char hexdigit(char c)
{
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	return c - '0';
}

struct emu_value *emu_value_new(char *buf)
{
	size_t i, len;
	struct emu_value *v;

	len = strlen(buf) / 2;

	v = malloc(sizeof(*v) + len);
	v->len = len;
	v->next = NULL;

	for (i = 0; i < len; i++)
		v->value[i] = (hexdigit(buf[2*i]) << 4) | hexdigit(buf[2*i+1]);

	free(buf);

	return v;
}

struct emu_value *emu_value_append(struct emu_value *first, struct emu_value *add)
{
	struct emu_value *p = first;

	if (!first)
		return add;

	while (p->next)
		p = p->next;

	p->next = add;

	return first;
}

void emu_value_free(struct emu_value *first)
{
	struct emu_value *next;

	while (first) {
		next = first->next;
		free(first);
		first = next;
	}
}

void emu_value_dump(const struct emu_value *first, FILE *f)
{
	if (!first) {
		fprintf(f, "EMPTY");
		return;
	}

	fprintf(f, "<");
	while (first->next) {
		dump_buffer_simple(first->value, first->len, f);
		fprintf(f, ">, <");
		first = first->next;
	}

	dump_buffer_simple(first->value, first->len, f);
	fprintf(f, ">");
}

const unsigned char *emu_value_get(const struct emu_value *v, size_t *plen)
{
	if (!v) {
		*plen = 0;

		return NULL;
	}

	*plen = v->len;

	return v->value;
}

struct emu_property *emu_property_new(char *name, struct emu_value *value)
{
	struct emu_property *prop = malloc(sizeof(*prop));

	prop->next = NULL;
	prop->name = name;
	prop->value = value;

	return prop;
}

struct emu_property *emu_property_append(struct emu_property *first, struct emu_property *add)
{
	struct emu_property *p = first;

	if (!first)
		return add;

	while (p->next)
		p = p->next;

	p->next = add;

	return first;
}

void emu_property_dump(const struct emu_property *first, FILE *f)
{
	if (!first) {
		fprintf(f, "EMPTY");
		return;
	}

	while (first->next) {
		fprintf(f, "\"%s\", ", first->name);
		first = first->next;
	}

	fprintf(f, "\"%s\"", first->name);
}

void emu_property_free(struct emu_property *first)
{
	struct emu_property *next;

	while (first) {
		next = first->next;

		free(first->name);
		emu_value_free(first->value);
		free(first);

		first = next;
	}
}

const struct emu_value *emu_property_get_value(const struct emu_property *prop, unsigned n)
{
	const struct emu_value *value;

	if (!prop)
		return NULL;

	for (value = prop->value; --n && value; value = value->next)
		;

	return value;
}

struct emu_df *emu_df_new(struct emu_property *props)
{
	struct emu_df *df = malloc(sizeof(*df));

	df->props = props;

	return df;
}

void emu_df_free(struct emu_df *df)
{
	if (!df)
		return;

	emu_property_free(df->props);
	free(df);
}

const struct emu_property *emu_df_get_property(const struct emu_df *df, const char *name)
{
	const struct emu_property *prop;

	if (!df)
		return NULL;

	for (prop = df->props; prop; prop = prop->next)
		if (!strcmp(prop->name, name))
			return prop;

	return NULL;
}
