#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/pagemap.h>
#include <linux/stat.h>
#include <linux/time.h>
#include <linux/jiffies.h>

#include "kwebdavfs.h"

const struct inode_operations kwebdavfs_file_inode_operations;

/*
 * Map a WebDAV URL to a stable inode number via djb2 hash.
 * Collisions are resolved by iget5_locked's test callback.
 */
static unsigned long url_to_ino(const char *url)
{
    unsigned long h = 5381;
    unsigned char c;
    if (!url)
        return 1;
    while ((c = *url++))
        h = h * 33 ^ (unsigned long)c;
    return h ? h : 1;
}

/* iget5_locked test: returns 1 if the inode's URL matches */
static int kwebdavfs_inode_test(struct inode *inode, void *data)
{
    struct kwebdavfs_inode_info *ei = KWEBDAVFS_I(inode);
    const char *url = data;
    if (!ei->url || !url)
        return 0;
    return strcmp(ei->url, url) == 0;
}

/* iget5_locked set: called for brand-new inodes to store their URL */
static int kwebdavfs_inode_set(struct inode *inode, void *data)
{
    struct kwebdavfs_inode_info *ei = KWEBDAVFS_I(inode);
    const char *url = data;
    ei->url = url ? kstrdup(url, GFP_KERNEL) : NULL;
    if (url && !ei->url)
        return -ENOMEM;
    return 0;
}

/**
 * kwebdavfs_iget - find or create an inode for the given WebDAV URL.
 *
 * If a matching inode already exists in the inode cache, it is returned
 * directly (no I_NEW flag).  Otherwise a new inode is allocated, its URL
 * is set, and it is returned with I_NEW set; the caller MUST finish
 * initialising it and then call unlock_new_inode().
 */
struct inode *kwebdavfs_iget(struct super_block *sb, const char *url)
{
    return iget5_locked(sb, url_to_ino(url),
                        kwebdavfs_inode_test,
                        kwebdavfs_inode_set,
                        (void *)url);
}

/**
 * kwebdavfs_get_inode - allocate and fully initialise a new inode.
 *
 * Used only for the root inode (created once during fill_super).  All
 * other inodes go through kwebdavfs_iget() so they are properly cached.
 */
struct inode *kwebdavfs_get_inode(struct super_block *sb, const struct inode *dir,
                                  umode_t mode, dev_t dev, const char *url)
{
    struct inode *inode = new_inode(sb);
    struct kwebdavfs_inode_info *ei;
    struct kwebdavfs_fs_info *fsi = KWEBDAVFS_SB(sb);

    if (!inode)
        return NULL;

    ei = KWEBDAVFS_I(inode);

    /* url is already stored by alloc_inode; set it here for get_inode path */
    ei->url = url ? kstrdup(url, GFP_KERNEL) : NULL;

    inode->i_ino = url_to_ino(url);
    inode_init_owner(&nop_mnt_idmap, inode, dir, mode);

    /* Override with mount options */
    inode->i_uid = fsi->uid;
    inode->i_gid = fsi->gid;

    inode_set_atime_to_ts(inode, current_time(inode));
    inode_set_mtime_to_ts(inode, current_time(inode));
    inode_set_ctime_to_ts(inode, current_time(inode));

    switch (mode & S_IFMT) {
    case S_IFREG:
        inode->i_op = &kwebdavfs_file_inode_operations;
        inode->i_fop = &kwebdavfs_file_operations;
        inode->i_mapping->a_ops = &kwebdavfs_aops;
        break;
    case S_IFDIR:
        inode->i_op = &kwebdavfs_dir_inode_operations;
        inode->i_fop = &kwebdavfs_dir_operations;
        /* Directory inodes start with i_nlink == 2 (for "." entry) */
        inc_nlink(inode);
        break;
    default:
        printk(KERN_ERR "kwebdavfs: unsupported file type: %o\n", mode);
        iput(inode);
        return NULL;
    }

    return inode;
}

int kwebdavfs_getattr(struct mnt_idmap *idmap, const struct path *path,
                      struct kstat *stat, u32 request_mask, unsigned int flags)
{
    struct inode *inode = d_inode(path->dentry);

    /*
     * Serve entirely from cached inode data.
     * Metadata is populated by readdir (PROPFIND Depth:1) and cached in
     * the inode by kwebdavfs_lookup.  No per-file HEAD requests.
     */
    generic_fillattr(idmap, STATX_BASIC_STATS, inode, stat);
    return 0;
}

int kwebdavfs_setattr(struct mnt_idmap *idmap, struct dentry *dentry,
                      struct iattr *iattr)
{
    struct inode *inode = d_inode(dentry);
    struct kwebdavfs_inode_info *ei = KWEBDAVFS_I(inode);
    int ret;

    /* UID/GID changes are not supported */
    if (iattr->ia_valid & (ATTR_UID | ATTR_GID))
        return -EPERM;

    ret = setattr_prepare(idmap, dentry, iattr);
    if (ret)
        return ret;

    /* Handle size changes (truncation / extension) */
    if (iattr->ia_valid & ATTR_SIZE) {
        loff_t newsize = iattr->ia_size;
        loff_t cursize = i_size_read(inode);
        struct kwebdavfs_fs_info *fsi = KWEBDAVFS_SB(inode->i_sb);

        mutex_lock(&ei->inode_mutex);

        if (newsize != cursize) {
            struct webdav_response resp;

            if (newsize == 0) {
                /* Truncate to zero: PUT with empty body */
                memset(&resp, 0, sizeof(resp));
                ret = kwebdavfs_http_request(fsi, WEBDAV_PUT, ei->url,
                                             "", 0, &resp);
                if (!ret && resp.status_code != 200 &&
                    resp.status_code != 201 && resp.status_code != 204)
                    ret = -EIO;
                kwebdavfs_free_response(&resp);
            } else {
                /* Resize: GET existing content, resize buffer, PUT back */
                struct webdav_response get_resp;
                char *buf;
                memset(&get_resp, 0, sizeof(get_resp));
                ret = kwebdavfs_http_request(fsi, WEBDAV_GET, ei->url,
                                             NULL, 0, &get_resp);
                if (!ret) {
                    buf = kvzalloc(newsize, GFP_KERNEL);
                    if (!buf) {
                        ret = -ENOMEM;
                    } else {
                        if (get_resp.data && get_resp.data_len > 0)
                            memcpy(buf, get_resp.data,
                                   min_t(size_t, get_resp.data_len, newsize));
                        memset(&resp, 0, sizeof(resp));
                        ret = kwebdavfs_http_request(fsi, WEBDAV_PUT,
                                                     ei->url, buf, newsize, &resp);
                        if (!ret && resp.status_code != 200 &&
                            resp.status_code != 201 && resp.status_code != 204)
                            ret = -EIO;
                        kwebdavfs_free_response(&resp);
                        kvfree(buf);
                    }
                }
                kwebdavfs_free_response(&get_resp);
            }

            if (!ret) {
                truncate_setsize(inode, newsize);
                ei->remote_size = newsize;
            }
        }

        mutex_unlock(&ei->inode_mutex);
        if (ret)
            return ret;
    }

    /* Apply the changes to the inode */
    setattr_copy(idmap, inode, iattr);
    mark_inode_dirty(inode);

    return 0;
}

const struct inode_operations kwebdavfs_file_inode_operations = {
    .getattr    = kwebdavfs_getattr,
    .setattr    = kwebdavfs_setattr,
};