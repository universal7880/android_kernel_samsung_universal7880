/*
 *  linux/fs/ext4/symlink.c
 *
 * Only fast symlinks left here - the rest is done by generic code. AV, 1999
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/symlink.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  ext4 symlink handling code
 */

#include <linux/fs.h>
#include <linux/jbd2.h>
#include <linux/namei.h>
#include "ext4.h"
#include "xattr.h"

#ifdef CONFIG_EXT4_FS_ENCRYPTION
static void *ext4_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	struct inode *inode = d_inode(dentry);
	struct page *page = NULL;
	const void *data;
	unsigned int size;
	void *result;

	if (!IS_ENCRYPTED(inode))
		return page_follow_link_light(dentry, nd);
	if (ext4_inode_is_fast_symlink(inode)) {
		data = EXT4_I(inode)->i_data;
		size = sizeof(EXT4_I(inode)->i_data);
	} else {
		page = read_mapping_page(inode->i_mapping, 0, NULL);
		if (IS_ERR(page))
			return page;
		data = page_address(page);
		size = PAGE_SIZE;
	}
	result = fscrypt_get_symlink(inode, data, size, nd);
	if (page)
		page_cache_release(page);
	return result;
}

static void ext4_put_link(struct dentry *dentry, struct nameidata *nd,
			  void *cookie)
{
	struct page *page = cookie;

	if (!page) {
		kfree(nd_get_link(nd));
	} else {
		kunmap(page);
		page_cache_release(page);
	}
}
#endif

static void *ext4_follow_fast_link(struct dentry *dentry, struct nameidata *nd)
{
	struct ext4_inode_info *ei = EXT4_I(dentry->d_inode);
	nd_set_link(nd, (char *) ei->i_data);
	return NULL;
}

const struct inode_operations ext4_symlink_inode_operations = {
	.readlink	= generic_readlink,
#ifdef CONFIG_EXT4_FS_ENCRYPTION
	.follow_link    = ext4_follow_link,
	.put_link       = ext4_put_link,
#else
	.follow_link	= page_follow_link_light,
	.put_link	= page_put_link,
#endif
	.setattr	= ext4_setattr,
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= ext4_listxattr,
	.removexattr	= generic_removexattr,
};

const struct inode_operations ext4_fast_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link    = ext4_follow_fast_link,
	.setattr	= ext4_setattr,
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= ext4_listxattr,
	.removexattr	= generic_removexattr,
};
