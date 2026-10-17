/* SPDX-License-Identifier: GPL-2.0 */
/* Preserve firmware boot data when completing the A5/A7 bootstrap DT. */
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/libfdt.h>
#include <linux/printk.h>
#include <linux/string.h>

#include "exynos7880-dt.h"

#define DT_MAX_SIZE (2 * 1024 * 1024)
#define DT_PATH_SIZE 512
#define DT_MAX_DEPTH 64

enum boot_node {
	BOOT_OTHER,
	BOOT_ROOT,
	BOOT_CHOSEN,
	BOOT_MEMORY,
	BOOT_RESERVED_ROOT,
	BOOT_RESERVED,
	BOOT_ECT,
};

/* libfdt's normal lookup also matches names without their unit addresses. */
static int __init exact_subnode(const void *dt, int parent, const char *name,
				int length)
{
	int node = parent, depth = 0, size;
	const char *actual;

	while ((node = fdt_next_node(dt, node, &depth)) >= 0 && depth > 0) {
		if (depth != 1)
			continue;
		actual = fdt_get_name(dt, node, &size);
		if (actual && size == length && !memcmp(actual, name, length))
			return node;
	}
	return -FDT_ERR_NOTFOUND;
}

static int __init exact_path(const void *dt, const char *path)
{
	const char *end;
	int node = 0;

	if (*path++ != '/')
		return -FDT_ERR_BADPATH;
	while (*path) {
		end = strchr(path, '/');
		if (!end)
			end = path + strlen(path);
		node = exact_subnode(dt, node, path, end - path);
		if (node < 0)
			return node;
		path = *end ? end + 1 : end;
	}
	return node;
}

static int __init window(unsigned long total, unsigned long offset,
			 unsigned long length)
{
	return offset <= total && length <= total - offset;
}

static int __init ranges_overlap(unsigned long a, unsigned long alen,
				 unsigned long b, unsigned long blen)
{
	return a <= b ? b - a < alen : a - b < blen;
}

/* Add board-selection constraints to libfdt's structural validation. */
int __init exynos7880_dt_validate(const void *dt, unsigned long size)
{
	const char *name;
	unsigned char children[DT_MAX_DEPTH] = { 0 };
	unsigned long total, so, ss, strings, slen, reserve, rlen, header;
	uint64_t address, bytes;
	uint32_t tag;
	int depth = 0, offset = 0, next, node, property, ret, root = 0;
	char path[DT_PATH_SIZE];

	if (!dt || ((unsigned long)dt & 7) || size < FDT_V17_SIZE)
		return -EINVAL;
	total = fdt_totalsize(dt);
	if (total > size || total < FDT_V17_SIZE || total > DT_MAX_SIZE ||
	    fdt_check_full(dt, size))
		return -EINVAL;

	/* Keep bounded depth and properties before child nodes. */
	for (;;) {
		tag = fdt_next_tag(dt, offset, &next);
		if (next < 0)
			return -EINVAL;
		if (tag == FDT_BEGIN_NODE) {
			if (depth == DT_MAX_DEPTH)
				return -EINVAL;
			if (depth)
				children[depth - 1] = 1;
			children[depth++] = 0;
			root = 1;
		} else if (tag == FDT_PROP) {
			if (!depth || children[depth - 1])
				return -EINVAL;
		} else if (tag == FDT_END_NODE) {
			if (!depth)
				return -EINVAL;
			depth--;
		} else if (tag == FDT_END) {
			if (depth || !root)
				return -EINVAL;
			break;
		}
		offset = next;
	}

	header = fdt_header_size(dt);
	so = fdt_off_dt_struct(dt);
	ss = fdt_version(dt) >= 17 ? fdt_size_dt_struct(dt) : next;
	strings = fdt_off_dt_strings(dt);
	slen = fdt_size_dt_strings(dt);
	reserve = fdt_off_mem_rsvmap(dt);
	if (so < header || (so & 3) || strings < header ||
	    !window(total, so, ss) || !window(total, strings, slen) ||
	    reserve < header || (reserve & 7) ||
	    ranges_overlap(so, ss, strings, slen))
		return -EINVAL;

	/* Reject overlapping blocks and overflowing reservations. */
	for (rlen = 0; ; rlen += 16) {
		if (!window(total, reserve, rlen + 16) ||
		    fdt_get_mem_rsv(dt, rlen / 16, &address, &bytes))
			return -EINVAL;
		if (!address && !bytes) {
			rlen += 16;
			break;
		}
		if (!bytes || address > (uint64_t)-1 - bytes)
			return -EINVAL;
	}
	if (ranges_overlap(reserve, rlen, so, ss) ||
	    ranges_overlap(reserve, rlen, strings, slen))
		return -EINVAL;

	/* Reject duplicate paths/properties rather than choosing the first. */
	depth = -1;
	node = -1;
	while ((node = fdt_next_node(dt, node, &depth)) >= 0 && depth >= 0) {
		ret = fdt_get_path(dt, node, path, sizeof(path));
		if (ret || exact_path(dt, path) != node)
			return -EINVAL;
		property = fdt_first_property_offset(dt, node);
		while (property >= 0) {
			const void *value;

			value = fdt_getprop_by_offset(dt, property,
						      &name, NULL);
			if (!value || !*name ||
			    value != fdt_getprop(dt, node, name, NULL))
				return -EINVAL;
			property = fdt_next_property_offset(dt, property);
		}
	}
	return 0;
}

static enum boot_node __init boot_node_kind(const char *path)
{
	if (!strcmp(path, "/"))
		return BOOT_ROOT;
	if (!strcmp(path, "/chosen") || !strcmp(path, "/chosen@0"))
		return BOOT_CHOSEN;
	if (!strncmp(path, "/memory", 7) && (!path[7] || path[7] == '@') &&
	    !strchr(path + 1, '/'))
		return BOOT_MEMORY;
	if (!strcmp(path, "/reserved-memory"))
		return BOOT_RESERVED_ROOT;
	if (!strncmp(path, "/reserved-memory/", 17) && !strchr(path + 17, '/'))
		return BOOT_RESERVED;
	if (!strcmp(path, "/ect"))
		return BOOT_ECT;
	return BOOT_OTHER;
}

static int __init same_property(const void *a, int an, const void *b, int bn,
				const char *name)
{
	int alen, blen;
	const void *av = fdt_getprop(a, an, name, &alen);
	const void *bv = fdt_getprop(b, bn, name, &blen);

	return av && bv && alen == blen && !memcmp(av, bv, alen);
}

static int __init is_phandle(const char *name)
{
	return !strcmp(name, "phandle") || !strcmp(name, "linux,phandle");
}

/* Board templates must share the bootstrap's boot-data layout. */
static int __init shared_boot_data(const void *a, const void *b)
{
	const char *name;
	char path[DT_PATH_SIZE];
	int pass, node, other, depth, property;
	enum boot_node kind;

	if (!same_property(a, 0, b, 0, "#address-cells") ||
	    !same_property(a, 0, b, 0, "#size-cells"))
		return -EOPNOTSUPP;
	for (pass = 0; pass < 2; pass++) {
		node = -1;
		depth = -1;
		while ((node = fdt_next_node(a, node, &depth)) >= 0 &&
		       depth >= 0) {
			if (fdt_get_path(a, node, path, sizeof(path)))
				return -EINVAL;
			kind = boot_node_kind(path);
			if (kind == BOOT_ROOT || kind == BOOT_OTHER)
				continue;
			other = exact_path(b, path);
			if (other < 0)
				return -EOPNOTSUPP;
			property = fdt_first_property_offset(a, node);
			while (property >= 0) {
				fdt_getprop_by_offset(a, property, &name, NULL);
				if (!is_phandle(name) &&
				    !same_property(a, node, b, other, name)) {
					pr_err("exynos7880: boot data differs: %s:%s\n",
					       path, name);
					return -EOPNOTSUPP;
				}
				property = fdt_next_property_offset(a,
								    property);
			}
		}
		/* Check both directions for board-only properties. */
		{
			const void *swap = a;

			a = b;
			b = swap;
		}
	}
	return 0;
}

static int __init boot_property(enum boot_node kind, const char *name,
				const void *value, int length)
{
	enum {
		CELL,
		ADDRESS,
		CELLS,
		STRING,
		STRINGS,
		EMPTY,
		BYTES,
		MAC,
		MEMORY
	} type;

	if (is_phandle(name))
		return -EOPNOTSUPP;
	if ((kind == BOOT_ROOT && !strcmp(name, "serial-number")) ||
	    !strcmp(name, "mac-address") ||
	    !strcmp(name, "local-mac-address") ||
	    !strcmp(name, "local-bd-address")) {
		type = kind == BOOT_ROOT && !strcmp(name, "serial-number")
			       ? STRING
			       : MAC;
	} else if (kind == BOOT_CHOSEN) {
		if (!strcmp(name, "bootargs") || !strcmp(name, "stdout-path") ||
		    !strcmp(name, "linux,stdout-path"))
			type = STRING;
		else if (!strcmp(name, "linux,initrd-start") ||
			 !strcmp(name, "linux,initrd-end"))
			type = ADDRESS;
		else if (!strcmp(name, "linux,usable-memory-range") ||
			 !strcmp(name, "linux,elfcorehdr"))
			type = CELLS;
		else if (!strcmp(name, "kaslr-seed") ||
			 !strcmp(name, "rng-seed"))
			type = BYTES;
		else
			return -EOPNOTSUPP;
	} else if (kind == BOOT_MEMORY) {
		if (!strcmp(name, "reg") ||
		    !strcmp(name, "linux,usable-memory"))
			type = CELLS;
		else if (!strcmp(name, "device_type"))
			type = MEMORY;
		else if (!strcmp(name, "status"))
			type = STRING;
		else if (!strcmp(name, "hotpluggable"))
			type = EMPTY;
		else
			return -EOPNOTSUPP;
	} else if (kind == BOOT_RESERVED_ROOT) {
		if (!strcmp(name, "#address-cells") ||
		    !strcmp(name, "#size-cells"))
			type = CELL;
		else if (!strcmp(name, "ranges"))
			type = BYTES;
		else
			return -EOPNOTSUPP;
	} else if (kind == BOOT_RESERVED) {
		if (!strcmp(name, "reg") || !strcmp(name, "size") ||
		    !strcmp(name, "alignment") || !strcmp(name, "alloc-ranges"))
			type = CELLS;
		else if (!strcmp(name, "compatible"))
			type = STRINGS;
		else if (!strcmp(name, "status"))
			type = STRING;
		else if (!strcmp(name, "no-map") || !strcmp(name, "reusable"))
			type = EMPTY;
		else
			return -EOPNOTSUPP;
	} else if (kind == BOOT_ECT && (!strcmp(name, "parameter_address") ||
					!strcmp(name, "parameter_size"))) {
		type = CELL;
	} else {
		return -EOPNOTSUPP;
	}
	if (length < 0)
		return 0; /* A known property was removed by the firmware. */
	switch (type) {
	case CELL:
		return length == 4 ? 0 : -EINVAL;
	case ADDRESS:
		return length == 4 || length == 8 ? 0 : -EINVAL;
	case CELLS:
		return length > 0 && !(length & 3) ? 0 : -EINVAL;
	case STRING:
		return length > 0 && strnlen(value, length) == length - 1
			       ? 0
			       : -EINVAL;
	case STRINGS:
		return length > 0 && !((const char *)value)[length - 1]
			       ? 0
			       : -EINVAL;
	case EMPTY:
		return !length ? 0 : -EINVAL;
	case MAC:
		return length == 6 ? 0 : -EINVAL;
	case MEMORY:
		return length == 7 && !memcmp(value, "memory", 7) ? 0 : -EINVAL;
	case BYTES:
		return 0;
	}
	return -EINVAL;
}

static int __init fdt_error(int ret)
{
	return ret == -FDT_ERR_NOSPACE ? -ENOSPC : -EINVAL;
}

/* Avoid libfdt treating an existing name@unit as the new unitless name. */
static int __init add_exact_subnode(void *dt, int parent, const char *name)
{
	char temporary[32] = "__exynos7880_dt@0";
	unsigned int length = strlen(temporary);
	int node = fdt_add_subnode(dt, parent, name), ret;

	if (node != -FDT_ERR_EXISTS)
		return node;
	while (fdt_subnode_offset(dt, parent, temporary) >= 0) {
		if (length + 1 >= sizeof(temporary))
			return -FDT_ERR_NOSPACE;
		temporary[length++] = '0';
		temporary[length] = 0;
	}
	node = fdt_add_subnode(dt, parent, temporary);
	if (node < 0)
		return node;
	ret = fdt_set_name(dt, node, name);
	return ret ? ret : node;
}

static int __init ensure_node(void *dt, const char *path)
{
	char parent[DT_PATH_SIZE], *name;
	int node = exact_path(dt, path);

	if (node >= 0)
		return node;
	if (boot_node_kind(path) == BOOT_OTHER)
		return -EOPNOTSUPP;
	memcpy(parent, path, strlen(path) + 1);
	name = strrchr(parent, '/');
	*name++ = 0;
	node = exact_path(dt, *parent ? parent : "/");
	if (node < 0)
		return -EINVAL;
	node = add_exact_subnode(dt, node, name);
	return node < 0 ? fdt_error(node) : node;
}

static int __init apply_property(void *dt, const char *path, const char *name,
				 const void *value, int length)
{
	int node,
		ret = boot_property(boot_node_kind(path), name, value, length);

	if (ret) {
		pr_err("exynos7880: unsupported firmware property: %s:%s\n",
		       path, name);
		return ret;
	}
	node = ensure_node(dt, path);
	if (node < 0)
		return node;
	if (length < 0) {
		ret = fdt_delprop(dt, node, name);
		if (ret == -FDT_ERR_NOTFOUND)
			return 0;
	} else {
		ret = fdt_setprop(dt, node, name, value, length);
	}
	return ret < 0 ? fdt_error(ret) : 0;
}

static int __init replay_changes(const void *input, const void *base, void *out)
{
	const void *value, *original;
	const char *name;
	char path[DT_PATH_SIZE];
	int node, other, target, depth = -1, property, length, oldlen, ret;
	enum boot_node kind;

	node = -1;
	while ((node = fdt_next_node(base, node, &depth)) >= 0 && depth >= 0) {
		fdt_get_path(base, node, path, sizeof(path));
		other = exact_path(input, path);
		if (other < 0) {
			kind = boot_node_kind(path);
			target = exact_path(out, path);
			if ((kind != BOOT_MEMORY && kind != BOOT_CHOSEN) ||
			    (target >= 0 &&
			     (fdt_getprop(out, target, "phandle", NULL) ||
			      fdt_getprop(out, target, "linux,phandle",
					  NULL)))) {
				pr_err("exynos7880: firmware removed node: %s\n",
				       path);
				return -EOPNOTSUPP;
			}
			if (target >= 0 && fdt_del_node(out, target))
				return -EINVAL;
			continue;
		}
		property = fdt_first_property_offset(base, node);
		while (property >= 0) {
			original = fdt_getprop_by_offset(base, property, &name,
							 &oldlen);
			value = fdt_getprop(input, other, name, &length);
			if (!value || length != oldlen ||
			    memcmp(value, original, length)) {
				ret = apply_property(out, path, name, value,
						     value ? length : -1);
				if (ret)
					return ret;
			}
			property = fdt_next_property_offset(base, property);
		}
	}
	node = -1;
	depth = -1;
	while ((node = fdt_next_node(input, node, &depth)) >= 0 && depth >= 0) {
		fdt_get_path(input, node, path, sizeof(path));
		other = exact_path(base, path);
		if (other < 0) {
			ret = ensure_node(out, path);
			if (ret < 0) {
				pr_err("exynos7880: unsupported node: %s\n",
				       path);
				return ret;
			}
		}
		property = fdt_first_property_offset(input, node);
		while (property >= 0) {
			value = fdt_getprop_by_offset(input, property, &name,
						      &length);
			if (other < 0 ||
			    !fdt_getprop(base, other, name, NULL)) {
				ret = apply_property(out, path, name, value,
						     length);
				if (ret)
					return ret;
			}
			property = fdt_next_property_offset(input, property);
		}
	}
	return 0;
}

static int __init copy_reservations(const void *input, const void *base,
				    const void *board, void *out)
{
	uint64_t a, asize, b, bsize;
	int n, count = fdt_num_mem_rsv(base), ret;

	if (count != fdt_num_mem_rsv(board))
		return -EOPNOTSUPP;
	for (n = 0; n < count; n++) {
		fdt_get_mem_rsv(base, n, &a, &asize);
		fdt_get_mem_rsv(board, n, &b, &bsize);
		if (a != b || asize != bsize)
			return -EOPNOTSUPP;
	}
	while (fdt_num_mem_rsv(out)) {
		ret = fdt_del_mem_rsv(out, 0);
		if (ret)
			return fdt_error(ret);
	}
	count = fdt_num_mem_rsv(input);
	for (n = 0; n < count; n++) {
		fdt_get_mem_rsv(input, n, &a, &asize);
		ret = fdt_add_mem_rsv(out, a, asize);
		if (ret)
			return fdt_error(ret);
	}
	return 0;
}

static int __init check_stdout(const void *dt)
{
	static const char *const names[] = {"stdout-path", "linux,stdout-path"};
	const char *value;
	char path[DT_PATH_SIZE], *options;
	int chosen = exact_path(dt, "/chosen"), n, length;

	if (chosen < 0)
		chosen = exact_path(dt, "/chosen@0");
	if (chosen < 0)
		return -EINVAL;
	for (n = 0; n < 2; n++) {
		value = fdt_getprop(dt, chosen, names[n], &length);
		if (!value)
			continue;
		if (length <= 0 || length > sizeof(path) ||
		    strnlen(value, length) != length - 1)
			return -EINVAL;
		memcpy(path, value, length);
		options = strchr(path, ':');
		if (options)
			*options = 0;
		if (fdt_path_offset(dt, path) < 0)
			return -EINVAL;
	}
	return 0;
}

/* Output is private until success. None of the three input trees is modified.
 */
int __init exynos7880_dt_compose(const void *input, unsigned long input_size,
				 const void *base, const void *board, void *out,
				 unsigned int out_size)
{
	int ret;

	if (!input || !base || !board || !out)
		return -EINVAL;
	if (out_size < FDT_V17_SIZE)
		return -ENOSPC;
	ret = exynos7880_dt_validate(input, input_size);
	if (ret)
		return ret;
	if (exynos7880_dt_validate(base, fdt_totalsize(base)) ||
	    exynos7880_dt_validate(board, fdt_totalsize(board)) ||
	    ((unsigned long)out & 7) || out_size > DT_MAX_SIZE ||
	    ranges_overlap((unsigned long)out, out_size, (unsigned long)input,
			   input_size) ||
	    ranges_overlap((unsigned long)out, out_size, (unsigned long)base,
			   fdt_totalsize(base)) ||
	    ranges_overlap((unsigned long)out, out_size, (unsigned long)board,
			   fdt_totalsize(board)))
		return -EINVAL;
	if (fdt_node_check_compatible(input, 0, "samsung,exynos7880-bootstrap") ||
	    fdt_node_check_compatible(base, 0, "samsung,exynos7880-bootstrap") ||
	    !fdt_node_check_compatible(board, 0, "samsung,exynos7880-bootstrap") ||
	    (exact_path(input, "/chosen") >= 0 &&
	     exact_path(input, "/chosen@0") >= 0))
		return -EINVAL;
	ret = shared_boot_data(base, board);
	if (ret)
		return ret;
	ret = fdt_open_into(board, out, out_size);
	if (ret)
		return fdt_error(ret);
	ret = copy_reservations(input, base, board, out);
	if (ret)
		return ret;
	ret = replay_changes(input, base, out);
	if (ret)
		return ret;
	fdt_set_boot_cpuid_phys(out, fdt_boot_cpuid_phys(input));
	ret = fdt_pack(out);
	if (ret)
		return fdt_error(ret);
	ret = exynos7880_dt_validate(out, out_size);
	if (ret)
		return ret;
	ret = shared_boot_data(input, out);
	return ret ? ret : check_stdout(out);
}
