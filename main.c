#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/mm.h>

#include "kwebdavfs.h"

MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Kernel WebDAV Filesystem for NextCloud");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");

static struct kmem_cache *kwebdavfs_inode_cache;

static struct inode *kwebdavfs_alloc_inode(struct super_block *sb)
{
    struct kwebdavfs_inode_info *ei;

    ei = kmem_cache_alloc(kwebdavfs_inode_cache, GFP_KERNEL);
    if (!ei)
        return NULL;

    /* Zero-initialise ALL custom fields so iget5_locked is safe */
    ei->url            = NULL;
    ei->etag           = NULL;
    ei->remote_size    = 0;
    memset(&ei->remote_mtime, 0, sizeof(ei->remote_mtime));
    INIT_LIST_HEAD(&ei->dir_cache);
    ei->dir_cache_until = 0;
    mutex_init(&ei->inode_mutex);

    return &ei->vfs_inode;
}

static void kwebdavfs_evict_inode(struct inode *inode)
{
    struct kwebdavfs_inode_info *ei = KWEBDAVFS_I(inode);

    /* Drop any cached directory entries before the inode is freed */
    mutex_lock(&ei->inode_mutex);
    kwebdavfs_free_dirents(&ei->dir_cache);
    INIT_LIST_HEAD(&ei->dir_cache);  /* reinit so destroy_inode sees empty list */
    ei->dir_cache_until = 0;
    mutex_unlock(&ei->inode_mutex);

    truncate_inode_pages_final(&inode->i_data);
    clear_inode(inode);
}

static void kwebdavfs_destroy_inode(struct inode *inode)
{
    struct kwebdavfs_inode_info *ei = KWEBDAVFS_I(inode);

    kfree(ei->url);
    kfree(ei->etag);
    /* dir_cache already freed and reinitialized in evict_inode */
    kmem_cache_free(kwebdavfs_inode_cache, ei);
}

static void kwebdavfs_put_super(struct super_block *sb)
{
    struct kwebdavfs_fs_info *fsi = sb->s_fs_info;

    if (fsi) {
        kfree(fsi->server_url);
        kfree(fsi->base_url);
        kfree(fsi->username);
        kfree(fsi->password);
        kfree(fsi->user_agent);
        kfree(fsi);
        sb->s_fs_info = NULL;
    }
}

static const struct super_operations kwebdavfs_sops = {
    .alloc_inode    = kwebdavfs_alloc_inode,
    .evict_inode    = kwebdavfs_evict_inode,
    .destroy_inode  = kwebdavfs_destroy_inode,
    .put_super      = kwebdavfs_put_super,
    .statfs         = simple_statfs,
};

struct kwebdavfs_mount_args {
    const char *dev_name;
    void *data;
};

static int kwebdavfs_fill_super(struct super_block *sb, void *data, int silent)
{
    struct kwebdavfs_fs_info *fsi;
    struct inode *root_inode;
    struct kwebdavfs_mount_args *args = data;
    const char *dev_name = args ? args->dev_name : NULL;
    char *options = args ? args->data : NULL;
    
    sb->s_blocksize = PAGE_SIZE;
    sb->s_blocksize_bits = PAGE_SHIFT;
    sb->s_magic = KWEBDAVFS_MAGIC;
    sb->s_op = &kwebdavfs_sops;
    sb->s_time_gran = 1;
    
    // Allocate filesystem-specific data
    fsi = kzalloc(sizeof(*fsi), GFP_KERNEL);
    if (!fsi)
        return -ENOMEM;
    
    sb->s_fs_info = fsi;
    
    // Parse mount options
    if (kwebdavfs_parse_options(fsi, options) < 0) {
        kfree(fsi);
        return -EINVAL;
    }

    /* Use device name (URL) as server_url if not set via options */
    if (!fsi->server_url && dev_name && *dev_name) {
        fsi->server_url = kstrdup(dev_name, GFP_KERNEL);
        if (!fsi->server_url) {
            kfree(fsi);
            return -ENOMEM;
        }
        if (strncmp(fsi->server_url, "https://", 8) == 0)
            fsi->use_ssl = true;
        printk(KERN_INFO "kwebdavfs: mounting %s (ssl=%s, timeout=%ds)\n",
               fsi->server_url, fsi->use_ssl ? "yes" : "no", fsi->timeout);
    }

    if (!fsi->server_url) {
        printk(KERN_ERR "kwebdavfs: server URL is required (pass as device or server= option)\n");
        kfree(fsi);
        return -EINVAL;
    }

    /* Derive base_url = scheme://host (no path) for converting PROPFIND hrefs */
    {
        const char *host_start = NULL;
        const char *path_start;
        size_t base_len;

        if (strncmp(fsi->server_url, "https://", 8) == 0)
            host_start = fsi->server_url + 8;
        else if (strncmp(fsi->server_url, "http://", 7) == 0)
            host_start = fsi->server_url + 7;

        if (host_start) {
            path_start = strchr(host_start, '/');
            base_len = path_start ? (size_t)(path_start - fsi->server_url)
                                  : strlen(fsi->server_url);
            fsi->base_url = kmalloc(base_len + 1, GFP_KERNEL);
            if (!fsi->base_url) {
                kfree(fsi);
                return -ENOMEM;
            }
            memcpy(fsi->base_url, fsi->server_url, base_len);
            fsi->base_url[base_len] = '\0';
        } else {
            fsi->base_url = kstrdup(fsi->server_url, GFP_KERNEL);
        }
    }
    
    // Create root inode
    root_inode = kwebdavfs_get_root_inode(sb);
    if (!root_inode) {
        kfree(fsi);
        return -ENOMEM;
    }
    
    sb->s_root = d_make_root(root_inode);
    if (!sb->s_root) {
        kfree(fsi);
        return -ENOMEM;
    }
    
    return 0;
}

static struct dentry *kwebdavfs_mount(struct file_system_type *fs_type,
                                     int flags, const char *dev_name, void *data)
{
    struct kwebdavfs_mount_args args = {
        .dev_name = dev_name,
        .data = data,
    };
    return mount_nodev(fs_type, flags, &args, kwebdavfs_fill_super);
}

static struct file_system_type kwebdavfs_type = {
    .owner      = THIS_MODULE,
    .name       = "kwebdavfs",
    .mount      = kwebdavfs_mount,
    .kill_sb    = kill_anon_super,
};

static void kwebdavfs_inode_init_once(void *foo)
{
    struct kwebdavfs_inode_info *ei = (struct kwebdavfs_inode_info *)foo;
    inode_init_once(&ei->vfs_inode);
}

static int __init kwebdavfs_init(void)
{
    int ret;
    
    printk(KERN_INFO "kwebdavfs: Initializing kernel WebDAV filesystem\n");
    
    // Create inode cache
    kwebdavfs_inode_cache = kmem_cache_create("kwebdavfs_inode_cache",
                                             sizeof(struct kwebdavfs_inode_info),
                                             0, SLAB_RECLAIM_ACCOUNT,
                                             kwebdavfs_inode_init_once);
    if (!kwebdavfs_inode_cache)
        return -ENOMEM;
    
    // Skip HTTP client initialization for now
    // ret = kwebdavfs_http_init();
    // if (ret)
    //     goto out_cache;
    
    // Register filesystem
    ret = register_filesystem(&kwebdavfs_type);
    if (ret)
        goto out_cache;
    
    return 0;

out_cache:
    kmem_cache_destroy(kwebdavfs_inode_cache);
    return ret;
}

static void __exit kwebdavfs_exit(void)
{
    printk(KERN_INFO "kwebdavfs: Unloading kernel WebDAV filesystem\n");
    
    unregister_filesystem(&kwebdavfs_type);
    // Skip HTTP cleanup for now
    // kwebdavfs_http_exit();
    
    rcu_barrier(); /* Wait for completion of call_rcu()'s */
    kmem_cache_destroy(kwebdavfs_inode_cache);
}

module_init(kwebdavfs_init);
module_exit(kwebdavfs_exit);