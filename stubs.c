#include <linux/kernel.h>
#include <linux/fs.h>
#include "kwebdavfs.h"

/* Stub implementations for missing symbols */

const struct file_operations kwebdavfs_file_operations = {
    .owner = THIS_MODULE,
};

const struct address_space_operations kwebdavfs_aops = {
};

const struct file_operations kwebdavfs_dir_operations = {
    .owner = THIS_MODULE,
};

const struct inode_operations kwebdavfs_dir_inode_operations = {
};

/* Stub HTTP functions */
int kwebdavfs_http_request(struct kwebdavfs_fs_info *fsi, enum webdav_method method,
                          const char *url, const char *body, size_t body_len,
                          struct webdav_response *response)
{
    printk(KERN_INFO "kwebdavfs: stub HTTP request for %s\n", url);
    return -EOPNOTSUPP;
}

void kwebdavfs_free_response(struct webdav_response *response)
{
    /* Nothing to free in stub */
}