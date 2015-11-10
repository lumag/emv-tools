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

#include "openemv/config.h"

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <libconfig.h>

#ifndef LIBCONFIG_VER_MAJOR
static void openemv_config_error(const config_t *config)
{
	fprintf(stderr, "libconfig: %s\n",
			config_error_text(config));
}
#else
static void openemv_config_error(const config_t *config)
{
	fprintf(stderr, "%s:%d: %s\n",
			config_error_file(config),
			config_error_line(config),
			config_error_text(config));
}
#endif

static config_t *_openemv_config;

static void openemv_init_config(void)
{
	config_t *config;
	int ret;
	const char *fname;

	config = malloc(sizeof(*_openemv_config));
	config_init(config);
	fname = getenv("OPENEMV_CONFIG");
	if (!fname)
		fname = OPENEMV_CONFIG_DIR "config.txt";

	ret = config_read_file(config, fname);

	if (ret != CONFIG_TRUE) {
		openemv_config_error(config);

		/* Do not let incorrect data live in our config */
		config_destroy(config);
		config_init(config);
	}

	_openemv_config = config;
}

const char *openemv_config_get_str(const char *path, const char *def)
{
	const char *value = def;

	if (!_openemv_config)
		openemv_init_config();

	if (_openemv_config)
		config_lookup_string(_openemv_config, path, &value);

	return value;
}

int openemv_config_get_int(const char *path, int def)
{
	int value = def;

	if (!_openemv_config)
		openemv_init_config();

	if (_openemv_config)
		config_lookup_int(_openemv_config, path, &value);

	return value;
}
