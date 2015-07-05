#ifndef EMU_AST_H
#define EMU_AST_H

#include <stdio.h>

struct emu_value;
struct emu_property;
struct emu_df;

struct emu_value *emu_value_new(char *buf);
struct emu_value *emu_value_append(struct emu_value *first, struct emu_value *add);
void emu_value_dump(const struct emu_value *first, FILE *f);
void emu_value_free(struct emu_value *first);
const unsigned char *emu_value_get(const struct emu_value *v, size_t *plen);

struct emu_property *emu_property_new(char *name, struct emu_value *value);
struct emu_property *emu_property_append(struct emu_property *first, struct emu_property *add);
void emu_property_dump(const struct emu_property *first, FILE *f);
void emu_property_free(struct emu_property *first);
const struct emu_value *emu_property_get_value(const struct emu_property *prop, unsigned n);

struct emu_df *emu_df_new(struct emu_property *props);
void emu_df_free(struct emu_df *df);
const struct emu_property *emu_df_get_property(const struct emu_df *df, const char *name);

static inline const unsigned char *emu_df_get_value(const struct emu_df *df, const char *name, unsigned n, size_t *plen)
{
	const struct emu_property *prop = emu_df_get_property(df, name);
	if (!prop) {
		*plen = 0;
		return NULL;
	}

	const struct emu_value *value = emu_property_get_value(prop, n);
	if (!value) {
		*plen = 0;
		return NULL;
	}

	const unsigned char *buf = emu_value_get(value, plen);

	return buf;
}

#endif
