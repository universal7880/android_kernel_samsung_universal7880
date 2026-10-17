/* SPDX-License-Identifier: GPL-2.0 */
/* Early A5/A7 identification using the bootloader's original /chosen. */
#include <linux/ctype.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/libfdt.h>
#include <linux/string.h>

#include "exynos7880-dt.h"

struct boot_value {
	const char *data;
	unsigned int length;
};

/* Reject duplicate identity arguments instead of choosing an arbitrary one. */
static int __init find_boot_value(const char *args, const char *key,
				 struct boot_value *value)
{
	unsigned int key_len = strlen(key);
	const char *start;

	value->data = NULL;
	while (*args) {
		while (isspace(*args))
			args++;
		start = args;
		while (*args && !isspace(*args))
			args++;
		if (args - start <= key_len ||
		    strncmp(start, key, key_len) || start[key_len] != '=')
			continue;
		if (value->data)
			return -EINVAL;
		value->data = start + key_len + 1;
		value->length = args - value->data;
	}

	return value->data && value->length ? 0 : -EINVAL;
}

static int __init parse_bootloader(const struct boot_value *value,
				  struct exynos7880_dt_board *board)
{
	unsigned int i;

	/* Family, regional suffix, then the alphanumeric firmware identifier. */
	if (value->length < 5 || value->length > 32)
		return -EINVAL;
	for (i = 0; i < value->length; i++)
		if (!isupper(value->data[i]) && !isdigit(value->data[i]))
			return -EINVAL;

	board->variant = value->data[4];
	if (!strncmp(value->data, "A520", 4) &&
	    strchr("FWKLS", board->variant))
		board->model = "a5y17lte";
	else if (!strncmp(value->data, "A720", 4) &&
		 strchr("FS", board->variant))
		board->model = "a7y17lte";
	else
		return -ENODEV;

	return 0;
}

static int __init parse_revision(const struct boot_value *value,
				unsigned int *revision)
{
	unsigned int i, number = 0;

	if (!value->length || value->length > 3)
		return -EINVAL;
	for (i = 0; i < value->length; i++) {
		if (!isdigit(value->data[i]))
			return -EINVAL;
		number = number * 10 + value->data[i] - '0';
	}
	if (number > 255)
		return -ERANGE;
	*revision = number;
	return 0;
}

/*
 * Return 1 for an identified bootstrap, 0 for an ordinary board DT, or a
 * negative error for an invalid bootstrap identity. Do not modify the FDT:
 * memory, initrd, reservations and other firmware changes remain intact.
 */
int __init exynos7880_dt_identify(const void *fdt,
				struct exynos7880_dt_board *board)
{
	struct exynos7880_dt_board identified;
	struct boot_value bootloader, revision;
	const char *args;
	int chosen, length, ret;

	ret = fdt_check_header(fdt);
	if (ret)
		return -EINVAL;
	ret = fdt_node_check_compatible(fdt, 0, "samsung,exynos7880-bootstrap");
	if (ret == 1 || ret == -FDT_ERR_NOTFOUND)
		return 0;
	if (ret)
		return -EINVAL;

	chosen = fdt_path_offset(fdt, "/chosen");
	if (chosen == -FDT_ERR_NOTFOUND)
		chosen = fdt_path_offset(fdt, "/chosen@0");
	if (chosen < 0)
		return -EINVAL;
	args = fdt_getprop(fdt, chosen, "bootargs", &length);
	if (!args || length <= 0 ||
	    strnlen(args, length) != length - 1)
		return -EINVAL;

	ret = find_boot_value(args, "androidboot.bootloader", &bootloader);
	if (ret)
		return ret;
	ret = find_boot_value(args, "androidboot.hw_rev", &revision);
	if (ret)
		return ret;
	ret = parse_bootloader(&bootloader, &identified);
	if (ret)
		return ret;
	ret = parse_revision(&revision, &identified.revision);
	if (ret)
		return ret;

	*board = identified;
	return 1;
}

#ifdef CONFIG_EXYNOS7880_BOARD_DTBS
static const char *__init
board_config_id(const struct exynos7880_dt_board *board)
{
	if (!strcmp(board->model, "a5y17lte")) {
		switch (board->variant) {
		case 'F':
			return "a5y17lte-eur";
		case 'W':
			return "a5y17lte-can";
		case 'K':
		case 'L':
		case 'S':
			return "a5y17lte-kor";
		}
	} else if (!strcmp(board->model, "a7y17lte")) {
		switch (board->variant) {
		case 'F':
			return "a7y17lte-eur";
		case 'S':
			return "a7y17lte-kor";
		}
	}
	return NULL;
}

static int __init read_revision(const void *fdt, const char *name,
				unsigned int *revision)
{
	const uint32_t *value;
	int length;

	value = fdt_getprop(fdt, 0, name, &length);
	if (!value || length != sizeof(*value))
		return -EINVAL;
	*revision = fdt32_to_cpu(*value);
	return *revision <= 255 ? 0 : -ERANGE;
}

/* Catalogue DTBs are generated from the existing board sources by Kbuild. */
int __init exynos7880_dt_select(const void *catalogue, unsigned long size,
				const struct exynos7880_dt_board *board,
				const void **bootstrap, const void **selected)
{
	const char *cursor = catalogue;
	const void *base = NULL, *match = NULL;
	const char *id = board_config_id(board), *value;
	unsigned long bytes, padded, i;
	unsigned int first, last;
	int length, ret;

	if (!id)
		return -ENODEV;
	while (size) {
		/* Other built-in DTBs may have stronger section alignment. */
		if (!*cursor) {
			bytes = size < 8 ? size : 8;
			for (i = 0; i < bytes; i++)
				if (cursor[i])
					return -EINVAL;
			cursor += bytes;
			size -= bytes;
			continue;
		}
		if (size < FDT_V17_SIZE || fdt_check_header(cursor))
			return -EINVAL;
		bytes = fdt_totalsize(cursor);
		if (bytes < FDT_V17_SIZE || bytes > size)
			return -EINVAL;
		padded = (bytes + 7) & ~7UL;
		if (padded > size)
			return -EINVAL;

		ret = fdt_node_check_compatible(cursor, 0,
						"samsung,exynos7880-bootstrap");
		if (!ret) {
			if (base)
				return -EINVAL;
			base = cursor;
		}
		value = fdt_getprop(cursor, 0, "samsung,board-id", &length);
		if (value && length == strlen(id) + 1 &&
		    !memcmp(value, id, length)) {
			ret = read_revision(cursor, "model_info-hw_rev",
					    &first);
			if (ret)
				return ret;
			ret = read_revision(cursor, "model_info-hw_rev_end",
					    &last);
			if (ret)
				return ret;
			if (first > last)
				return -EINVAL;
			if (board->revision >= first &&
			    board->revision <= last) {
				if (match)
					return -EINVAL;
				match = cursor;
			}
		}
		cursor += padded;
		size -= padded;
	}
	if (!base || !match)
		return -ENODEV;
	*bootstrap = base;
	*selected = match;
	return 0;
}
#endif
