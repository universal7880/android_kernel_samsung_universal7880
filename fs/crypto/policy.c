/*
 * Encryption policy functions for per-file encryption support.
 *
 * Copyright (C) 2015, Google, Inc.
 * Copyright (C) 2015, Motorola Mobility.
 *
 * Written by Michael Halcrow, 2015.
 * Modified by Jaegeuk Kim, 2015.
 */

#include <linux/random.h>
#include <linux/string.h>
#include <linux/mount.h>
#include "fscrypt_private.h"

static size_t fscrypt_policy_size(u8 version)
{
	switch (version) {
	case 0:
		return sizeof(struct fscrypt_policy);
	case FSCRYPT_POLICY_V2:
		return sizeof(struct fscrypt_policy_v2);
	default:
		return 0;
	}
}

int fscrypt_policy_from_context(union fscrypt_policy_data *policy,
				const union fscrypt_context *ctx, int size)
{
	if (size == sizeof(ctx->v1) &&
	    ctx->format == FS_ENCRYPTION_CONTEXT_FORMAT_V1) {
		policy->v1.version = 0;
		policy->v1.contents_encryption_mode = ctx->v1.contents_encryption_mode;
		policy->v1.filenames_encryption_mode = ctx->v1.filenames_encryption_mode;
		policy->v1.flags = ctx->v1.flags;
		memcpy(policy->v1.master_key_descriptor,
		       ctx->v1.master_key_descriptor, FS_KEY_DESCRIPTOR_SIZE);
		return 0;
	}

	if (size == sizeof(ctx->v2) &&
	    ctx->format == FS_ENCRYPTION_CONTEXT_FORMAT_V2 &&
	    !memchr_inv(ctx->v2.__reserved, 0, sizeof(ctx->v2.__reserved))) {
		policy->v2.version = FSCRYPT_POLICY_V2;
		policy->v2.contents_encryption_mode = ctx->v2.contents_encryption_mode;
		policy->v2.filenames_encryption_mode = ctx->v2.filenames_encryption_mode;
		policy->v2.flags = ctx->v2.flags;
		memset(policy->v2.__reserved, 0, sizeof(policy->v2.__reserved));
		memcpy(policy->v2.master_key_identifier, ctx->v2.master_key_identifier,
		       FSCRYPT_KEY_IDENTIFIER_SIZE);
		return 0;
	}
	return -EINVAL;
}

static int get_policy(struct inode *inode, union fscrypt_policy_data *policy)
{
	union fscrypt_context ctx;
	int ret;

	ret = inode->i_sb->s_cop->get_context(inode, &ctx, sizeof(ctx));
	if (ret < 0)
		return ret;
	return fscrypt_policy_from_context(policy, &ctx, ret);
}

static int set_context(struct inode *inode,
		       const union fscrypt_policy_data *policy, void *fs_data)
{
	union fscrypt_context ctx = {};
	size_t size;

	if (policy->version == FSCRYPT_POLICY_V2) {
		ctx.v2.format = FS_ENCRYPTION_CONTEXT_FORMAT_V2;
		ctx.v2.contents_encryption_mode = policy->v2.contents_encryption_mode;
		ctx.v2.filenames_encryption_mode = policy->v2.filenames_encryption_mode;
		ctx.v2.flags = policy->v2.flags;
		memcpy(ctx.v2.master_key_identifier, policy->v2.master_key_identifier,
		       FSCRYPT_KEY_IDENTIFIER_SIZE);
		get_random_bytes(ctx.v2.nonce, sizeof(ctx.v2.nonce));
		size = sizeof(ctx.v2);
	} else {
		ctx.v1.format = FS_ENCRYPTION_CONTEXT_FORMAT_V1;
		ctx.v1.contents_encryption_mode = policy->v1.contents_encryption_mode;
		ctx.v1.filenames_encryption_mode = policy->v1.filenames_encryption_mode;
		ctx.v1.flags = policy->v1.flags;
		memcpy(ctx.v1.master_key_descriptor, policy->v1.master_key_descriptor,
		       FS_KEY_DESCRIPTOR_SIZE);
		get_random_bytes(ctx.v1.nonce, sizeof(ctx.v1.nonce));
		size = sizeof(ctx.v1);
	}

	return inode->i_sb->s_cop->set_context(inode, &ctx, size, fs_data);
}

static int validate_new_policy(struct inode *inode,
			       const union fscrypt_policy_data *policy)
{
	if (policy->version == FSCRYPT_POLICY_V2) {
		if (!inode->i_sb->s_cop->supports_v2 ||
		    policy->v2.contents_encryption_mode != FS_ENCRYPTION_MODE_AES_256_XTS ||
		    policy->v2.filenames_encryption_mode != FS_ENCRYPTION_MODE_AES_256_CTS ||
		    (policy->v2.flags & ~FS_POLICY_FLAGS_VALID) ||
		    memchr_inv(policy->v2.__reserved, 0, sizeof(policy->v2.__reserved)))
			return -EINVAL;

		return fscrypt_verify_key_added(inode->i_sb,
						policy->v2.master_key_identifier);
	}

	if (!fscrypt_valid_enc_modes(policy->v1.contents_encryption_mode,
				     policy->v1.filenames_encryption_mode) ||
	    (policy->v1.flags & ~FS_POLICY_FLAGS_VALID))
		return -EINVAL;
	return 0;
}

static bool policies_equal(const union fscrypt_policy_data *a,
			   const union fscrypt_policy_data *b)
{
	return a->version == b->version &&
	       !memcmp(a, b, fscrypt_policy_size(a->version));
}

int fscrypt_ioctl_set_policy(struct file *filp, const void __user *arg)
{
	union fscrypt_policy_data policy, old_policy;
	struct inode *inode = file_inode(filp);
	size_t size;
	u8 version;
	int ret;

	if (get_user(version, (const u8 __user *)arg))
		return -EFAULT;
	size = fscrypt_policy_size(version);
	if (!size)
		return -EINVAL;
	if (copy_from_user(&policy, arg, size))
		return -EFAULT;
	if (policy.version != version)
		return -EINVAL;
	if (!inode_owner_or_capable(inode))
		return -EACCES;

	ret = mnt_want_write_file(filp);
	if (ret)
		return ret;
	inode_lock(inode);

	ret = get_policy(inode, &old_policy);
	if (ret == -ENODATA) {
		if (!S_ISDIR(inode->i_mode))
			ret = -ENOTDIR;
		else if (IS_DEADDIR(inode))
			ret = -ENOENT;
		else if (!inode->i_sb->s_cop->empty_dir(inode))
			ret = -ENOTEMPTY;
		else {
			ret = validate_new_policy(inode, &policy);
			if (!ret)
				ret = set_context(inode, &policy, NULL);
		}
	} else if (!ret) {
		ret = policies_equal(&policy, &old_policy) ? 0 : -EEXIST;
	} else if (ret == -ERANGE || ret == -EINVAL) {
		ret = -EEXIST;
	}

	inode_unlock(inode);
	mnt_drop_write_file(filp);
	return ret;
}
EXPORT_SYMBOL(fscrypt_ioctl_set_policy);

int fscrypt_ioctl_get_policy(struct file *filp, void __user *arg)
{
	union fscrypt_policy_data policy;
	struct inode *inode = file_inode(filp);
	int ret;

	if (!IS_ENCRYPTED(inode))
		return -ENODATA;
	ret = get_policy(inode, &policy);
	if (ret)
		return ret == -ERANGE ? -EINVAL : ret;
	if (policy.version != 0)
		return -EINVAL;
	return copy_to_user(arg, &policy.v1, sizeof(policy.v1)) ? -EFAULT : 0;
}
EXPORT_SYMBOL(fscrypt_ioctl_get_policy);

int fscrypt_ioctl_get_policy_ex(struct file *filp, void __user *arg)
{
	struct fscrypt_get_policy_ex_arg __user *uarg = arg;
	struct inode *inode = file_inode(filp);
	union fscrypt_policy_data policy;
	u64 user_size;
	size_t size;
	int ret;

	if (!IS_ENCRYPTED(inode))
		return -ENODATA;
	if (get_user(user_size, &uarg->policy_size))
		return -EFAULT;
	ret = get_policy(inode, &policy);
	if (ret)
		return ret;
	size = fscrypt_policy_size(policy.version);
	if (size > user_size)
		return -EOVERFLOW;
	if (copy_to_user(&uarg->policy, &policy, size) ||
	    put_user(size, &uarg->policy_size))
		return -EFAULT;
	return 0;
}
EXPORT_SYMBOL_GPL(fscrypt_ioctl_get_policy_ex);

/**
 * fscrypt_has_permitted_context() - is a file's encryption policy permitted
 *				     within its directory?
 *
 * @parent: inode for parent directory
 * @child: inode for file being looked up, opened, or linked into @parent
 *
 * Filesystems must call this before permitting access to an inode in a
 * situation where the parent directory is encrypted (either before allowing
 * ->lookup() to succeed, or for a regular file before allowing it to be opened)
 * and before any operation that involves linking an inode into an encrypted
 * directory, including link, rename, and cross rename.  It enforces the
 * constraint that within a given encrypted directory tree, all files use the
 * same encryption policy.  The pre-access check is needed to detect potentially
 * malicious offline violations of this constraint, while the link and rename
 * checks are needed to prevent online violations of this constraint.
 *
 * Return: 1 if permitted, 0 if forbidden.  If forbidden, the caller must fail
 * the filesystem operation with EPERM.
 */
int fscrypt_has_permitted_context(struct inode *parent, struct inode *child)
{
	const struct fscrypt_info *parent_ci, *child_ci;
	union fscrypt_policy_data parent_policy, child_policy;
	int res;

	/* No restrictions on file types which are never encrypted */
	if (!S_ISREG(child->i_mode) && !S_ISDIR(child->i_mode) &&
	    !S_ISLNK(child->i_mode))
		return 1;

	/* No restrictions if the parent directory is unencrypted */
	if (!IS_ENCRYPTED(parent))
		return 1;

	/* Encrypted directories must not contain unencrypted files */
	if (!IS_ENCRYPTED(child))
		return 0;

	/*
	 * Both parent and child are encrypted, so verify they use the same
	 * encryption policy.  Compare the fscrypt_info structs if the keys are
	 * available, otherwise retrieve and compare the fscrypt_contexts.
	 *
	 * Note that the fscrypt_context retrieval will be required frequently
	 * when accessing an encrypted directory tree without the key.
	 * Performance-wise this is not a big deal because we already don't
	 * really optimize for file access without the key (to the extent that
	 * such access is even possible), given that any attempted access
	 * already causes a fscrypt_context retrieval and keyring search.
	 *
	 * In any case, if an unexpected error occurs, fall back to "forbidden".
	 */

	res = fscrypt_get_encryption_info(parent);
	if (res)
		return 0;
	res = fscrypt_get_encryption_info(child);
	if (res)
		return 0;
	parent_ci = parent->i_crypt_info;
	child_ci = child->i_crypt_info;

	if (parent_ci && child_ci)
		return policies_equal(&parent_ci->ci_policy, &child_ci->ci_policy);

	if (get_policy(parent, &parent_policy) || get_policy(child, &child_policy))
		return 0;

	return policies_equal(&parent_policy, &child_policy);
}
EXPORT_SYMBOL(fscrypt_has_permitted_context);

/**
 * fscrypt_inherit_context() - Sets a child context from its parent
 * @parent: Parent inode from which the context is inherited.
 * @child:  Child inode that inherits the context from @parent.
 * @fs_data:  private data given by FS.
 * @preload:  preload child i_crypt_info if true
 *
 * Return: 0 on success, -errno on failure
 */
int fscrypt_inherit_context(struct inode *parent, struct inode *child,
						void *fs_data, bool preload)
{
	struct fscrypt_info *ci;
	int res;

	res = fscrypt_get_encryption_info(parent);
	if (res < 0)
		return res;

	ci = parent->i_crypt_info;
	if (ci == NULL)
		return -ENOKEY;

	res = set_context(child, &ci->ci_policy, fs_data);
	if (res)
		return res;
	return preload ? fscrypt_get_encryption_info(child): 0;
}
EXPORT_SYMBOL(fscrypt_inherit_context);
