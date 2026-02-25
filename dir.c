#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/jiffies.h>

#include "kwebdavfs.h"

/* Ensure ei->dir_cache is populated and fresh.
 * MUST be called with ei->inode_mutex held. */
static int kwebdavfs_fill_dir_cache(struct kwebdavfs_inode_info *ei,
                                     struct kwebdavfs_fs_info *fsi)
{
    struct list_head fresh;
    int ret;

    /* Cache valid if populated AND (ttl=0/infinite OR still within TTL) */
    if (!list_empty(&ei->dir_cache)) {
        if (fsi->dir_ttl_jiffies == 0)
            return 0;
        if (!time_after(jiffies, ei->dir_cache_until))
            return 0;
    }

    INIT_LIST_HEAD(&fresh);
    ret = kwebdavfs_propfind(fsi, ei->url, &fresh);
    if (ret < 0)
        return ret;

    /* Swap old cache for new */
    kwebdavfs_free_dirents(&ei->dir_cache);
    list_replace_init(&fresh, &ei->dir_cache);
    ei->dir_cache_until = jiffies + fsi->dir_ttl_jiffies; /* unused when ttl=0 */
    return 0;
}

static int kwebdavfs_readdir(struct file *file, struct dir_context *ctx)
{
    struct inode *inode = file_inode(file);
    struct kwebdavfs_inode_info *ei = KWEBDAVFS_I(inode);
    struct kwebdavfs_fs_info *fsi = KWEBDAVFS_SB(inode->i_sb);
    struct webdav_dirent *entry;
    loff_t pos = ctx->pos;
    loff_t entry_idx;
    int ret = 0;

    if (!S_ISDIR(inode->i_mode))
        return -ENOTDIR;

    if (pos == 0) {
        if (!dir_emit_dot(file, ctx))
            return 0;
        ctx->pos = ++pos;
    }
    if (pos == 1) {
        if (!dir_emit_dotdot(file, ctx))
            return 0;
        ctx->pos = ++pos;
    }

    if (!ei->url)
        return 0;

    mutex_lock(&ei->inode_mutex);

    ret = kwebdavfs_fill_dir_cache(ei, fsi);
    if (ret < 0) {
        printk(KERN_ERR "kwebdavfs: PROPFIND failed for %s: %d\n", ei->url, ret);
        mutex_unlock(&ei->inode_mutex);
        return ret;
    }

    entry_idx = 0;
    list_for_each_entry(entry, &ei->dir_cache, list) {
        if (!entry->name || entry->name[0] == '\0') {
            entry_idx++;
            continue;
        }
        if (2 + entry_idx < pos) {
            entry_idx++;
            continue;
        }

        if (!dir_emit(ctx, entry->name, strlen(entry->name),
                      inode->i_ino + 2 + entry_idx,
                      entry->is_dir ? DT_DIR : DT_REG)) {
            goto out_unlock;
        }
        ctx->pos = 2 + (++entry_idx);
    }

out_unlock:
    mutex_unlock(&ei->inode_mutex);
    return ret;
}

static struct dentry *kwebdavfs_lookup(struct inode *dir, struct dentry *dentry,
                                      unsigned int flags)
{
    struct kwebdavfs_inode_info *dir_ei = KWEBDAVFS_I(dir);
    struct kwebdavfs_fs_info *fsi = KWEBDAVFS_SB(dir->i_sb);
    struct webdav_dirent *entry;
    struct inode *inode = NULL;
    const char *name = dentry->d_name.name;
    int ret;

    if (!dir_ei->url)
        return ERR_PTR(-ENOENT);

    mutex_lock(&dir_ei->inode_mutex);

    ret = kwebdavfs_fill_dir_cache(dir_ei, fsi);
    if (ret < 0) {
        mutex_unlock(&dir_ei->inode_mutex);
        return ERR_PTR(ret);
    }

    list_for_each_entry(entry, &dir_ei->dir_cache, list) {
        if (!entry->name || strcmp(entry->name, name) != 0)
            continue;


        umode_t mode = entry->is_dir ? S_IFDIR | 0755 : S_IFREG | 0644;
        char *child_url = kwebdavfs_href_to_url(fsi, entry->href);
        if (!child_url) {
            ret = -ENOMEM;
            break;
        }

        /* Use iget5_locked so the same URL always maps to the same inode */
        inode = kwebdavfs_iget(dir->i_sb, child_url);
        kfree(child_url);
        if (!inode) {
            ret = -ENOMEM;
            break;
        }

        if (inode->i_state & I_NEW) {
            /* Brand-new inode – set up VFS fields */
            inode->i_mode  = mode;
            inode->i_uid   = fsi->uid;
            inode->i_gid   = fsi->gid;
            if (S_ISDIR(mode)) {
                inode->i_op  = &kwebdavfs_dir_inode_operations;
                inode->i_fop = &kwebdavfs_dir_operations;
                set_nlink(inode, 2);
            } else {
                inode->i_op  = &kwebdavfs_file_inode_operations;
                inode->i_fop = &kwebdavfs_file_operations;
                inode->i_mapping->a_ops = &kwebdavfs_aops;
                set_nlink(inode, 1);
            }
            inode_set_atime_to_ts(inode, entry->mtime);
            unlock_new_inode(inode);
        } else {
            /* Existing cached inode – keep uid/gid in sync with mount opts */
            inode->i_uid = fsi->uid;
            inode->i_gid = fsi->gid;
        }

        /* Always refresh metadata from latest PROPFIND data */
        i_size_write(inode, entry->size);
        KWEBDAVFS_I(inode)->remote_size = entry->size;
        inode_set_mtime_to_ts(inode, entry->mtime);
        KWEBDAVFS_I(inode)->remote_mtime = entry->mtime;
        if (entry->etag) {
            kfree(KWEBDAVFS_I(inode)->etag);
            KWEBDAVFS_I(inode)->etag = kstrdup(entry->etag, GFP_KERNEL);
        }
        break;
    }

    mutex_unlock(&dir_ei->inode_mutex);

    if (ret < 0)
        return ERR_PTR(ret);

    return d_splice_alias(inode, dentry);
}

static int kwebdavfs_create(struct mnt_idmap *idmap, struct inode *dir,
                           struct dentry *dentry, umode_t mode, bool excl)
{
    struct kwebdavfs_inode_info *dir_ei = KWEBDAVFS_I(dir);
    struct kwebdavfs_fs_info *fsi = KWEBDAVFS_SB(dir->i_sb);
    struct webdav_response response;
    struct inode *inode;
    char *file_path, *file_url;
    const char *name = dentry->d_name.name;
    int ret;

    if (!dir_ei->url)
        return -ENOENT;

    /* Build path for new file, percent-encoding special chars in name */
    {
        char *enc = kwebdavfs_url_encode_segment(name);
        if (!enc)
            return -ENOMEM;
        file_path = kasprintf(GFP_KERNEL, "%s/%s",
                             dir_ei->url + strlen(fsi->server_url), enc);
        kfree(enc);
    }
    if (!file_path)
        return -ENOMEM;

    file_url = kwebdavfs_build_url(fsi, file_path);
    kfree(file_path);
    if (!file_url)
        return -ENOMEM;

    mutex_lock(&dir_ei->inode_mutex);

    /* Create empty file on server with PUT */
    memset(&response, 0, sizeof(response));
    ret = kwebdavfs_http_request(fsi, WEBDAV_PUT, file_url, "", 0, &response);

    if (ret < 0) {
        printk(KERN_ERR "kwebdavfs: failed to create %s: %d\n", file_url, ret);
        goto out_free_url;
    }

    if (response.status_code != 201 && response.status_code != 200) {
        printk(KERN_ERR "kwebdavfs: server returned %d for PUT %s\n", 
               response.status_code, file_url);
        ret = -EIO;
        goto out_free_response;
    }

    /* Create local inode */
    inode = kwebdavfs_get_inode(dir->i_sb, dir, mode, 0, file_url);
    if (!inode) {
        ret = -ENOMEM;
        goto out_free_response;
    }

    /* Invalidate dir cache — list_empty check in fill_dir_cache will re-fetch */
    kwebdavfs_free_dirents(&dir_ei->dir_cache);

    /* Update directory mtime */
    inode_set_mtime_to_ts(dir, current_time(dir));
    inode_set_ctime_to_ts(dir, current_time(dir));
    mark_inode_dirty(dir);

    /* Insert new dentry */
    d_instantiate(dentry, inode);

out_free_response:
    kwebdavfs_free_response(&response);
out_free_url:
    mutex_unlock(&dir_ei->inode_mutex);
    kfree(file_url);  /* inode has its own kstrdup'd copy */
    return ret;
}

static struct dentry *kwebdavfs_mkdir(struct mnt_idmap *idmap, struct inode *dir,
                          struct dentry *dentry, umode_t mode)
{
    struct kwebdavfs_inode_info *dir_ei = KWEBDAVFS_I(dir);
    struct kwebdavfs_fs_info *fsi = KWEBDAVFS_SB(dir->i_sb);
    struct webdav_response response;
    struct inode *inode;
    char *dir_path, *dir_url;
    const char *name = dentry->d_name.name;
    int ret;

    if (!dir_ei->url)
        return ERR_PTR(-ENOENT);

    /* Build path for new directory, percent-encoding special chars in name */
    {
        char *enc = kwebdavfs_url_encode_segment(name);
        if (!enc)
            return ERR_PTR(-ENOMEM);
        dir_path = kasprintf(GFP_KERNEL, "%s/%s/",
                            dir_ei->url + strlen(fsi->server_url), enc);
        kfree(enc);
    }
    if (!dir_path)
        return ERR_PTR(-ENOMEM);

    dir_url = kwebdavfs_build_url(fsi, dir_path);
    kfree(dir_path);
    if (!dir_url)
        return ERR_PTR(-ENOMEM);

    mutex_lock(&dir_ei->inode_mutex);

    /* Create directory on server with MKCOL */
    memset(&response, 0, sizeof(response));
    ret = kwebdavfs_http_request(fsi, WEBDAV_MKCOL, dir_url, NULL, 0, &response);

    if (ret < 0) {
        printk(KERN_ERR "kwebdavfs: failed to create directory %s: %d\n", dir_url, ret);
        goto out_free_url;
    }

    if (response.status_code != 201) {
        printk(KERN_ERR "kwebdavfs: server returned %d for MKCOL %s\n", 
               response.status_code, dir_url);
        ret = (response.status_code == 409) ? -EEXIST : -EIO;
        goto out_free_response;
    }

    /* Create local inode */
    inode = kwebdavfs_get_inode(dir->i_sb, dir, S_IFDIR | mode, 0, dir_url);
    if (!inode) {
        ret = -ENOMEM;
        goto out_free_response;
    }

    /* Invalidate dir cache — list_empty check in fill_dir_cache will re-fetch */
    kwebdavfs_free_dirents(&dir_ei->dir_cache);

    /* Update parent directory */
    inc_nlink(dir);
    inode_set_mtime_to_ts(dir, current_time(dir));
    inode_set_ctime_to_ts(dir, current_time(dir));
    mark_inode_dirty(dir);

    /* Insert new dentry */
    d_instantiate(dentry, inode);

out_free_response:
    kwebdavfs_free_response(&response);
out_free_url:
    mutex_unlock(&dir_ei->inode_mutex);
    kfree(dir_url);  /* inode has its own kstrdup'd copy */
    return ERR_PTR(ret);
}

static int kwebdavfs_unlink(struct inode *dir, struct dentry *dentry)
{
    struct inode *inode = d_inode(dentry);
    struct kwebdavfs_inode_info *ei = KWEBDAVFS_I(inode);
    struct kwebdavfs_fs_info *fsi = KWEBDAVFS_SB(dir->i_sb);
    struct webdav_response response;
    int ret;

    if (!ei->url)
        return -ENOENT;

    mutex_lock(&ei->inode_mutex);

    /* Delete file on server */
    memset(&response, 0, sizeof(response));
    ret = kwebdavfs_http_request(fsi, WEBDAV_DELETE, ei->url, NULL, 0, &response);

    if (ret < 0) {
        printk(KERN_ERR "kwebdavfs: failed to delete %s: %d\n", ei->url, ret);
        goto out_unlock;
    }

    if (response.status_code != 200 && response.status_code != 204 && response.status_code != 404) {
        printk(KERN_ERR "kwebdavfs: server returned %d for DELETE %s\n", 
               response.status_code, ei->url);
        ret = -EIO;
        goto out_free_response;
    }

    /* Invalidate parent dir cache — list_empty check will re-fetch */
    kwebdavfs_free_dirents(&KWEBDAVFS_I(dir)->dir_cache);

    /* Update directory mtime */
    inode_set_mtime_to_ts(dir, current_time(dir));
    inode_set_ctime_to_ts(dir, current_time(dir));
    mark_inode_dirty(dir);

    /* Update inode link count */
    drop_nlink(inode);

out_free_response:
    kwebdavfs_free_response(&response);
out_unlock:
    mutex_unlock(&ei->inode_mutex);
    return ret;
}

static int kwebdavfs_rename(struct mnt_idmap *idmap,
                            struct inode *old_dir, struct dentry *old_dentry,
                            struct inode *new_dir, struct dentry *new_dentry,
                            unsigned int flags)
{
    struct inode *src_inode = d_inode(old_dentry);
    struct kwebdavfs_inode_info *src_ei     = KWEBDAVFS_I(src_inode);
    struct kwebdavfs_inode_info *old_dir_ei = KWEBDAVFS_I(old_dir);
    struct kwebdavfs_inode_info *new_dir_ei = KWEBDAVFS_I(new_dir);
    struct kwebdavfs_fs_info *fsi = KWEBDAVFS_SB(old_dir->i_sb);
    const char *new_name = new_dentry->d_name.name;
    bool is_dir = S_ISDIR(src_inode->i_mode);
    char *dst_path, *dst_url;
    int ret;

    /* Only support simple rename/move; no RENAME_EXCHANGE or RENAME_WHITEOUT */
    if (flags & ~RENAME_NOREPLACE)
        return -EINVAL;

    if (!src_ei->url || !new_dir_ei->url)
        return -ENOENT;

    /* Build destination URL, percent-encoding special chars in new_name */
    {
        char *enc = kwebdavfs_url_encode_segment(new_name);
        if (!enc)
            return -ENOMEM;
        if (is_dir)
            dst_path = kasprintf(GFP_KERNEL, "%s/%s/",
                                 new_dir_ei->url + strlen(fsi->server_url), enc);
        else
            dst_path = kasprintf(GFP_KERNEL, "%s/%s",
                                 new_dir_ei->url + strlen(fsi->server_url), enc);
        kfree(enc);
    }
    if (!dst_path)
        return -ENOMEM;

    dst_url = kwebdavfs_build_url(fsi, dst_path);
    kfree(dst_path);
    if (!dst_url)
        return -ENOMEM;

    /* Send MOVE to server; overwrite=true unless RENAME_NOREPLACE */
    ret = kwebdavfs_http_move(fsi, src_ei->url, dst_url,
                              !(flags & RENAME_NOREPLACE));
    if (ret < 0) {
        kfree(dst_url);
        return ret;
    }

    /* Update the moved inode's URL */
    kfree(src_ei->url);
    src_ei->url = dst_url;  /* ownership transferred */

    /* Invalidate both parent directory caches */
    mutex_lock(&old_dir_ei->inode_mutex);
    kwebdavfs_free_dirents(&old_dir_ei->dir_cache);
    mutex_unlock(&old_dir_ei->inode_mutex);

    if (new_dir != old_dir) {
        mutex_lock(&new_dir_ei->inode_mutex);
        kwebdavfs_free_dirents(&new_dir_ei->dir_cache);
        mutex_unlock(&new_dir_ei->inode_mutex);
    }

    /* Update link counts and timestamps */
    if (is_dir) {
        drop_nlink(old_dir);
        inc_nlink(new_dir);
    }
    inode_set_mtime_to_ts(old_dir, current_time(old_dir));
    mark_inode_dirty(old_dir);
    if (new_dir != old_dir) {
        inode_set_mtime_to_ts(new_dir, current_time(new_dir));
        mark_inode_dirty(new_dir);
    }

    return 0;
}

const struct file_operations kwebdavfs_dir_operations = {
    .owner          = THIS_MODULE,
    .iterate_shared = kwebdavfs_readdir,
    .llseek         = generic_file_llseek,
};

const struct inode_operations kwebdavfs_dir_inode_operations = {
    .lookup         = kwebdavfs_lookup,
    .create         = kwebdavfs_create,
    .mkdir          = kwebdavfs_mkdir,
    .rename         = kwebdavfs_rename,
    .unlink         = kwebdavfs_unlink,
    .rmdir          = kwebdavfs_unlink,  /* Same as unlink for WebDAV */
    .getattr        = kwebdavfs_getattr,
    .setattr        = kwebdavfs_setattr,
};