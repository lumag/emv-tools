#ifndef EMU_AST_H
#define EMU_AST_H

#include <stdio.h>

struct emu_value;
struct emu_property;
struct emu_df;

struct emu_value *value_new(char *buf);
struct emu_value *value_append(struct emu_value *first, struct emu_value *add);
void value_dump(const struct emu_value *first, FILE *f);
void value_free(struct emu_value *first);
const unsigned char *value_get(const struct emu_value *v, size_t *plen);

struct emu_property *property_new(char *name, struct emu_value *value);
struct emu_property *property_append(struct emu_property *first, struct emu_property *add);
void property_dump(const struct emu_property *first, FILE *f);
void property_free(struct emu_property *first);
const struct emu_value *property_get_value(const struct emu_property *prop, unsigned n);

struct emu_df *df_new(struct emu_property *props);
void df_free(struct emu_df *df);
const struct emu_property *df_get_property(const struct emu_df *df, const char *name);

#endif
