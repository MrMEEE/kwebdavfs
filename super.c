#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/parser.h>
#include <linux/slab.h>
#include <linux/stat.h>

#include "kwebdavfs.h"

/* Mount option tokens */
enum {
    opt_server_url,
    opt_username,
    opt_password,
    opt_user_agent,
    opt_timeout,
    opt_ttl,
    opt_ssl,
    opt_verify_ssl,
    opt_uid,
    opt_gid,
    opt_err
};

static const match_table_t tokens = {
    {opt_server_url,    "server=%s"},
    {opt_username,      "username=%s"},
    {opt_password,      "password=%s"},
    {opt_user_agent,    "user_agent=%s"},
    {opt_timeout,       "timeout=%d"},
    {opt_ttl,           "ttl=%d"},
    {opt_ssl,           "ssl"},
    {opt_verify_ssl,    "verify_ssl"},
    {opt_uid,           "uid=%d"},
    {opt_gid,           "gid=%d"},
    {opt_err,           NULL}
};

int kwebdavfs_parse_options(struct kwebdavfs_fs_info *fsi, char *options)
{
    substring_t args[MAX_OPT_ARGS];
    char *p;
    int token;
    int ret = 0;

    /* Set defaults */
    fsi->server_url = NULL;
    fsi->username = NULL;
    fsi->password = NULL;
    fsi->user_agent = kstrdup("kwebdavfs/" KWEBDAVFS_VERSION, GFP_KERNEL);
    fsi->timeout = 30; /* 30 second default timeout */
    fsi->dir_ttl_jiffies = KWEBDAVFS_DIR_TTL_DEFAULT_SECS * HZ; /* 5 min default */
    fsi->use_ssl = false;
    fsi->verify_ssl = true;
    fsi->uid = current_uid();
    fsi->gid = current_gid();
    mutex_init(&fsi->fs_mutex);

    if (!options)
        return -EINVAL;

    while ((p = strsep(&options, ",")) != NULL) {
        if (!*p)
            continue;

        token = match_token(p, tokens, args);
        switch (token) {
        case opt_server_url:
            kfree(fsi->server_url);
            fsi->server_url = match_strdup(&args[0]);
            if (!fsi->server_url) {
                ret = -ENOMEM;
                goto out_err;
            }
            /* Check if URL starts with https:// */
            if (strncmp(fsi->server_url, "https://", 8) == 0)
                fsi->use_ssl = true;
            break;

        case opt_username:
            kfree(fsi->username);
            fsi->username = match_strdup(&args[0]);
            if (!fsi->username) {
                ret = -ENOMEM;
                goto out_err;
            }
            break;

        case opt_password:
            kfree(fsi->password);
            fsi->password = match_strdup(&args[0]);
            if (!fsi->password) {
                ret = -ENOMEM;
                goto out_err;
            }
            break;

        case opt_user_agent:
            kfree(fsi->user_agent);
            fsi->user_agent = match_strdup(&args[0]);
            if (!fsi->user_agent) {
                ret = -ENOMEM;
                goto out_err;
            }
            break;

        case opt_timeout:
            if (match_int(&args[0], &fsi->timeout)) {
                ret = -EINVAL;
                goto out_err;
            }
            if (fsi->timeout <= 0 || fsi->timeout > 300) {
                printk(KERN_ERR "kwebdavfs: timeout must be between 1-300 seconds\n");
                ret = -EINVAL;
                goto out_err;
            }
            break;

        case opt_ttl: {
            int ttl_secs;
            if (match_int(&args[0], &ttl_secs)) {
                ret = -EINVAL;
                goto out_err;
            }
            if (ttl_secs < 0) {
                printk(KERN_ERR "kwebdavfs: ttl must be >= 0 (0 = write-invalidation only)\n");
                ret = -EINVAL;
                goto out_err;
            }
            /* ttl=0 means never expire via time — only write-invalidation */
            /* 0 = infinite (write-invalidation only); stored as 0 in dir_ttl_jiffies */
            fsi->dir_ttl_jiffies = ttl_secs ? (unsigned long)ttl_secs * HZ : 0;
            break;
        }

        case opt_ssl:
            fsi->use_ssl = true;
            break;

        case opt_verify_ssl:
            fsi->verify_ssl = true;
            break;

        case opt_uid: {
            int uid_val;
            if (match_int(&args[0], &uid_val)) {
                ret = -EINVAL;
                goto out_err;
            }
            fsi->uid = make_kuid(current_user_ns(), uid_val);
            if (!uid_valid(fsi->uid)) {
                printk(KERN_ERR "kwebdavfs: invalid uid %d\n", uid_val);
                ret = -EINVAL;
                goto out_err;
            }
            break;
        }

        case opt_gid: {
            int gid_val;
            if (match_int(&args[0], &gid_val)) {
                ret = -EINVAL;
                goto out_err;
            }
            fsi->gid = make_kgid(current_user_ns(), gid_val);
            if (!gid_valid(fsi->gid)) {
                printk(KERN_ERR "kwebdavfs: invalid gid %d\n", gid_val);
                ret = -EINVAL;
                goto out_err;
            }
            break;
        }

        default:
            printk(KERN_ERR "kwebdavfs: unrecognized mount option \"%s\"\n", p);
            ret = -EINVAL;
            goto out_err;
        }
    }

    /* Validate required options - server_url may also come from dev_name */
    if (!fsi->server_url) {
        /* Not an error here - fill_super will check dev_name */
    }

    return 0;

out_err:
    kfree(fsi->server_url);
    kfree(fsi->base_url);
    kfree(fsi->username);
    kfree(fsi->password);
    kfree(fsi->user_agent);
    return ret;
}

struct inode *kwebdavfs_get_root_inode(struct super_block *sb)
{
    struct kwebdavfs_fs_info *fsi = KWEBDAVFS_SB(sb);
    struct inode *inode;
    struct kwebdavfs_inode_info *ei;
    char *root_url;

    /* Create root inode */
    inode = kwebdavfs_get_inode(sb, NULL, S_IFDIR | 0755, 0, fsi->server_url);
    if (!inode)
        return NULL;

    ei = KWEBDAVFS_I(inode);
    
    /* Build root URL */
    root_url = kwebdavfs_build_url(fsi, "/");
    if (!root_url) {
        iput(inode);
        return NULL;
    }
    
    kfree(ei->url);
    ei->url = root_url;

    /* Set root inode properties */
    inode->i_ino = 1;
    inode->i_op = &kwebdavfs_dir_inode_operations;
    inode->i_fop = &kwebdavfs_dir_operations;
    inode->i_uid = fsi->uid;
    inode->i_gid = fsi->gid;
    inode_set_atime_to_ts(inode, current_time(inode));
    inode_set_mtime_to_ts(inode, current_time(inode));
    inode_set_ctime_to_ts(inode, current_time(inode));

    return inode;
}

char *kwebdavfs_build_url(struct kwebdavfs_fs_info *fsi, const char *path)
{
    char *url;
    size_t server_len, path_len, total_len;
    
    if (!fsi->server_url || !path)
        return NULL;
    
    server_len = strlen(fsi->server_url);
    path_len = strlen(path);
    
    /* Remove trailing slash from server URL if present */
    if (server_len > 0 && fsi->server_url[server_len - 1] == '/')
        server_len--;
    
    /* Ensure path starts with '/' */
    if (path[0] != '/') {
        total_len = server_len + 1 + path_len + 1;
        url = kmalloc(total_len, GFP_KERNEL);
        if (!url)
            return NULL;
        snprintf(url, total_len, "%.*s/%s", (int)server_len, fsi->server_url, path);
    } else {
        total_len = server_len + path_len + 1;
        url = kmalloc(total_len, GFP_KERNEL);
        if (!url)
            return NULL;
        snprintf(url, total_len, "%.*s%s", (int)server_len, fsi->server_url, path);
    }
    
    return url;
}

/*
 * Convert a PROPFIND href (absolute path like /remote.php/dav/files/mjp/foo)
 * to a full URL using just scheme://host, avoiding double-path duplication.
 */
char *kwebdavfs_href_to_url(struct kwebdavfs_fs_info *fsi, const char *href)
{
    char *url;
    size_t base_len, href_len, total_len;

    if (!fsi->base_url || !href)
        return NULL;

    /* If href looks like a full URL already, just duplicate it */
    if (strncmp(href, "http://", 7) == 0 || strncmp(href, "https://", 8) == 0)
        return kstrdup(href, GFP_KERNEL);

    base_len  = strlen(fsi->base_url);
    href_len  = strlen(href);
    total_len = base_len + href_len + 1;

    url = kmalloc(total_len, GFP_KERNEL);
    if (!url)
        return NULL;

    /* href always starts with '/' from WebDAV PROPFIND */
    snprintf(url, total_len, "%s%s", fsi->base_url,
             href[0] == '/' ? href : "/");
    if (href[0] != '/')
        strlcat(url, href, total_len);

    return url;
}