/*
 * fscrypt_private.h
 *
 * Copyright (C) 2015, Google, Inc.
 *
 * This contains encryption key functions.
 *
 * Written by Michael Halcrow, Ildar Muslukhov, and Uday Savagaonkar, 2015.
 */

#ifndef _FSCRYPT_PRIVATE_H
#define _FSCRYPT_PRIVATE_H

#define __FS_HAS_ENCRYPTION 1
#include <linux/fscrypt.h>
#include <crypto/hash.h>

/* Encryption parameters */
#define FS_IV_SIZE			16
#define FS_KEY_DERIVATION_NONCE_SIZE	16

/**
 * Encryption context for inode
 *
 * Protector format:
 *  1 byte: Protector format (1 = this version)
 *  1 byte: File contents encryption mode
 *  1 byte: File names encryption mode
 *  1 byte: Flags
 *  8 bytes: Master Key descriptor
 *  16 bytes: Encryption Key derivation nonce
 */
struct fscrypt_context_v1 {
	u8 format;
	u8 contents_encryption_mode;
	u8 filenames_encryption_mode;
	u8 flags;
	u8 master_key_descriptor[FS_KEY_DESCRIPTOR_SIZE];
	u8 nonce[FS_KEY_DERIVATION_NONCE_SIZE];
} __packed;

#define FS_ENCRYPTION_CONTEXT_FORMAT_V1		1
#define FS_ENCRYPTION_CONTEXT_FORMAT_V2		2

struct fscrypt_context_v2 {
	u8 format;
	u8 contents_encryption_mode;
	u8 filenames_encryption_mode;
	u8 flags;
	u8 __reserved[4];
	u8 master_key_identifier[FSCRYPT_KEY_IDENTIFIER_SIZE];
	u8 nonce[FS_KEY_DERIVATION_NONCE_SIZE];
} __packed;

union fscrypt_context {
	u8 format;
	struct fscrypt_context_v1 v1;
	struct fscrypt_context_v2 v2;
};

union fscrypt_policy_data {
	u8 version;
	struct fscrypt_policy v1;
	struct fscrypt_policy_v2 v2;
};

int fscrypt_policy_from_context(union fscrypt_policy_data *policy,
				const union fscrypt_context *ctx, int size);


/**
 * For encrypted symlinks, the ciphertext length is stored at the beginning
 * of the string in little-endian format.
 */
struct fscrypt_symlink_data {
	__le16 len;
	char encrypted_path[1];
} __packed;

/*
 * A pointer to this structure is stored in the file system's in-core
 * representation of an inode.
 */
struct fscrypt_info {
	struct inode *ci_inode;
	struct list_head ci_master_key_link;
	u8 ci_data_mode;
	u8 ci_filename_mode;
	u8 ci_flags;
	struct crypto_ablkcipher *ci_ctfm;
	struct crypto_cipher *ci_essiv_tfm;
	union fscrypt_policy_data ci_policy;
	struct key *ci_key;
};

typedef enum {
	FS_DECRYPT = 0,
	FS_ENCRYPT,
} fscrypt_direction_t;

#define FSCRYPT_MIN_KEY_SIZE	16

#define FS_CTX_REQUIRES_FREE_ENCRYPT_FL		0x00000001
#define FS_CTX_HAS_BOUNCE_BUFFER_FL		0x00000002

static inline const struct user_key_payload *user_key_payload(const struct key *key)
{
	return (struct user_key_payload *)rcu_dereference_key(key);
}

/* bio stuffs */
#define REQ_OP_READ	READ
#define REQ_OP_WRITE	WRITE
#define bio_op(bio)	((bio)->bi_rw & 1)

static inline void bio_set_op_attrs(struct bio *bio, unsigned op,
		unsigned op_flags)
{
	bio->bi_rw = op | op_flags;
}

static inline bool fscrypt_valid_enc_modes(u32 contents_mode,
					   u32 filenames_mode)
{
	if (contents_mode == FS_ENCRYPTION_MODE_AES_128_CBC &&
	    filenames_mode == FS_ENCRYPTION_MODE_AES_128_CTS)
		return true;

	if (contents_mode == FS_ENCRYPTION_MODE_AES_256_XTS &&
	    filenames_mode == FS_ENCRYPTION_MODE_AES_256_CTS)
		return true;

	if (contents_mode == FS_ENCRYPTION_MODE_SPECK128_256_XTS &&
	    filenames_mode == FS_ENCRYPTION_MODE_SPECK128_256_CTS)
		return true;

	return false;
}

/* crypto.c */
extern struct kmem_cache *fscrypt_info_cachep;
extern int fscrypt_initialize(unsigned int cop_flags);
extern int fscrypt_do_page_crypto(const struct inode *inode,
				  fscrypt_direction_t rw, u64 lblk_num,
				  struct page *src_page,
				  struct page *dest_page,
				  unsigned int len, unsigned int offs,
				  gfp_t gfp_flags);
extern struct page *fscrypt_alloc_bounce_page(struct fscrypt_ctx *ctx,
					      gfp_t gfp_flags);
extern const struct dentry_operations fscrypt_d_ops;

extern void __printf(3, 4) __cold
fscrypt_msg(struct super_block *sb, const char *level, const char *fmt, ...);

#define fscrypt_warn(sb, fmt, ...)		\
	fscrypt_msg(sb, KERN_WARNING, fmt, ##__VA_ARGS__)
#define fscrypt_err(sb, fmt, ...)		\
	fscrypt_msg(sb, KERN_ERR, fmt, ##__VA_ARGS__)

/* fname.c */
extern int fname_encrypt(struct inode *inode, const struct qstr *iname,
			 u8 *out, unsigned int olen);
extern bool fscrypt_fname_encrypted_size(const struct inode *inode,
					 u32 orig_len, u32 max_len,
					 u32 *encrypted_len_ret);

/* hkdf.c */

struct fscrypt_hkdf {
	struct crypto_shash *hmac_tfm;
};

extern int fscrypt_init_hkdf(struct fscrypt_hkdf *hkdf, const u8 *master_key,
			     unsigned int master_key_size);

/*
 * The list of contexts in which fscrypt uses HKDF.  These values are used as
 * the first byte of the HKDF application-specific info string to guarantee that
 * info strings are never repeated between contexts.  This ensures that all HKDF
 * outputs are unique and cryptographically isolated, i.e. knowledge of one
 * output doesn't reveal another.
 */
#define HKDF_CONTEXT_KEY_IDENTIFIER	1
#define HKDF_CONTEXT_PER_FILE_KEY	2
#define HKDF_CONTEXT_PER_MODE_KEY	3

extern int fscrypt_hkdf_expand(struct fscrypt_hkdf *hkdf, u8 context,
			       const u8 *info, unsigned int infolen,
			       u8 *okm, unsigned int okmlen);

extern void fscrypt_destroy_hkdf(struct fscrypt_hkdf *hkdf);

/* keyring.c */

/*
 * fscrypt_master_key_secret - secret key material of an in-use master key
 */
struct fscrypt_master_key_secret {

	/*
	 * For v2 policy keys: HKDF context keyed by this master key.
	 * For v1 policy keys: not set (hkdf.hmac_tfm == NULL).
	 */
	struct fscrypt_hkdf	hkdf;

	/* Size of the raw key in bytes.  Set even if ->raw isn't set. */
	u32			size;

	/* For v1 policy keys: the raw key.  Wiped for v2 policy keys. */
	u8			raw[FS_MAX_KEY_SIZE];

};

/*
 * fscrypt_master_key - an in-use master key
 *
 * This represents a master encryption key which has been added to the
 * filesystem and can be used to "unlock" the encrypted files which were
 * encrypted with it.
 */
struct fscrypt_master_key {

	/*
	 * The secret key material.  After FS_IOC_REMOVE_ENCRYPTION_KEY is
	 * executed, this is wiped and no new inodes can be unlocked with this
	 * key; however, there may still be inodes in ->mk_decrypted_inodes
	 * which could not be evicted.  As long as some inodes still remain,
	 * FS_IOC_REMOVE_ENCRYPTION_KEY can be retried, or
	 * FS_IOC_ADD_ENCRYPTION_KEY can add the secret again.
	 *
	 * Locking: protected by key->sem (outer) and mk_secret_sem (inner).
	 * The reason for two locks is that key->sem also protects modifying
	 * mk_users, which ranks it above the semaphore for the keyring key
	 * type, which is in turn above page faults (via keyring_read).  But
	 * sometimes filesystems call fscrypt_get_encryption_info() from within
	 * a transaction, which ranks it below page faults.  So we need a
	 * separate lock which protects mk_secret but not also mk_users.
	 */
	struct fscrypt_master_key_secret	mk_secret;
	struct rw_semaphore			mk_secret_sem;

	/*
	 * For v1 policy keys: an arbitrary key descriptor which was assigned by
	 * userspace (->descriptor).
	 *
	 * For v2 policy keys: a cryptographic hash of this key (->identifier).
	 */
	struct fscrypt_key_specifier		mk_spec;

	/*
	 * Keyring which contains a key of type 'key_type_fscrypt_user' for each
	 * user who has added this key.  Normally each key will be added by just
	 * one user, but it's possible that multiple users share a key, and in
	 * that case we need to keep track of those users so that one user can't
	 * remove the key before the others want it removed too.
	 *
	 * This is NULL for v1 policy keys; those can only be added by root.
	 *
	 * Locking: in addition to this keyrings own semaphore, this is
	 * protected by the master key's key->sem, so we can do atomic
	 * search+insert.  It can also be searched without taking any locks, but
	 * in that case the returned key may have already been removed.
	 */
	struct key		*mk_users;

	/*
	 * Length of ->mk_decrypted_inodes, plus one if mk_secret is present.
	 * Once this goes to 0, the master key is removed from ->s_master_keys.
	 * The 'struct fscrypt_master_key' will continue to live as long as the
	 * 'struct key' whose payload it is, but we won't let this reference
	 * count rise again.
	 */
	atomic_t		mk_refcount;

	/*
	 * List of inodes that were unlocked using this key.  This allows the
	 * inodes to be evicted efficiently if the key is removed.
	 */
	struct list_head	mk_decrypted_inodes;
	spinlock_t		mk_decrypted_inodes_lock;

};

static inline bool
is_master_key_secret_present(const struct fscrypt_master_key_secret *secret)
{
	/*
	 * The READ_ONCE() is only necessary for fscrypt_drop_inode() and
	 * fscrypt_key_describe().  These run in atomic context, so they can't
	 * take ->mk_secret_sem and thus 'secret' can change concurrently which
	 * would be a data race.  But they only need to know whether the secret
	 * *was* present at the time of check, so READ_ONCE() suffices.
	 */
	return READ_ONCE(secret->size) != 0;
}

static inline const char *master_key_spec_type(
				const struct fscrypt_key_specifier *spec)
{
	switch (spec->type) {
	case FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR:
		return "descriptor";
	case FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER:
		return "identifier";
	}
	return "[unknown]";
}

static inline int master_key_spec_len(const struct fscrypt_key_specifier *spec)
{
	switch (spec->type) {
	case FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR:
		return FS_KEY_DESCRIPTOR_SIZE;
	case FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER:
		return FSCRYPT_KEY_IDENTIFIER_SIZE;
	}
	return 0;
}

extern struct key *
fscrypt_find_master_key(struct super_block *sb,
			const struct fscrypt_key_specifier *mk_spec);

extern int fscrypt_verify_key_added(struct super_block *sb,
				    const u8 identifier[FSCRYPT_KEY_IDENTIFIER_SIZE]);

extern int __init fscrypt_init_keyring(void);
extern void __exit fscrypt_exit_keyring(void);

/* keyinfo.c */
extern void __exit fscrypt_essiv_cleanup(void);

#endif /* _FSCRYPT_PRIVATE_H */
