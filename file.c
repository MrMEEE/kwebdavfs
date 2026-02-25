#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/buffer_head.h>
#include <linux/writeback.h>

#include "kwebdavfs.h"

static int kwebdavfs_read_folio(struct file *file, struct folio *folio)
{
    struct page *page = &folio->page;
    struct inode *inode = page->mapping->host;
    struct kwebdavfs_inode_info *ei = KWEBDAVFS_I(inode);
    struct kwebdavfs_fs_info *fsi = KWEBDAVFS_SB(inode->i_sb);
    struct webdav_response response;
    char *kaddr;
    loff_t offset = page_offset(page);
    size_t len = PAGE_SIZE;
    int ret = 0;

    if (!ei->url) {
        ret = -ENOENT;
        goto out_unlock;
    }

    /* Adjust length if we're at the end of the file */
    if (offset + len > i_size_read(inode))
        len = i_size_read(inode) - offset;

    if (len <= 0) {
        /* Beyond end of file, zero fill */
        kaddr = kmap(page);
        memset(kaddr, 0, PAGE_SIZE);
        kunmap(page);
        folio_mark_uptodate(folio);
        folio_unlock(folio);
        return 0;
    }

    mutex_lock(&ei->inode_mutex);

    /* Send GET request to fetch file content */
    memset(&response, 0, sizeof(response));
    ret = kwebdavfs_http_request(fsi, WEBDAV_GET, ei->url, NULL, 0, &response);

    if (ret < 0) {
        printk(KERN_ERR "kwebdavfs: failed to fetch %s: %d\n", ei->url, ret);
        goto out_unlock_mutex;
    }

    if (response.status_code != 200) {
        printk(KERN_ERR "kwebdavfs: server returned %d for %s\n", 
               response.status_code, ei->url);
        ret = (response.status_code == 404) ? -ENOENT : -EIO;
        goto out_free_response;
    }

    /* Map the page and copy data */
    kaddr = kmap(page);
    
    if (response.data && response.data_len > offset) {
        size_t copy_len = min_t(size_t, len, response.data_len - offset);
        memcpy(kaddr, response.data + offset, copy_len);
        
        /* Zero fill the rest of the page */
        if (copy_len < PAGE_SIZE)
            memset(kaddr + copy_len, 0, PAGE_SIZE - copy_len);
    } else {
        /* No data or offset beyond data, zero fill */
        memset(kaddr, 0, PAGE_SIZE);
    }
    
    kunmap(page);

    /* Update inode size if server reports different size */
    if (response.content_length >= 0 && 
        response.content_length != i_size_read(inode)) {
        i_size_write(inode, response.content_length);
        ei->remote_size = response.content_length;
    }

    folio_mark_uptodate(folio);

out_free_response:
    kwebdavfs_free_response(&response);
out_unlock_mutex:
    mutex_unlock(&ei->inode_mutex);
out_unlock:
    if (ret < 0) {
        /* Zero fill on error */
        kaddr = kmap(page);
        memset(kaddr, 0, PAGE_SIZE);
        kunmap(page);
        /* Note: folio_set_error may not exist in all kernel versions */
    }
    
    folio_unlock(folio);
    return ret;
}

static ssize_t kwebdavfs_file_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
    return generic_file_read_iter(iocb, iter);
}

static ssize_t kwebdavfs_file_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
    struct file *file = iocb->ki_filp;
    struct inode *inode = file_inode(file);
    struct kwebdavfs_inode_info *ei = KWEBDAVFS_I(inode);
    struct kwebdavfs_fs_info *fsi = KWEBDAVFS_SB(inode->i_sb);
    struct webdav_response response;
    char *buffer;
    size_t count = iov_iter_count(iter);
    int ret;

    if (!ei->url)
        return -ENOENT;

    /* Allocate buffer for the write data */
    buffer = kmalloc(count, GFP_KERNEL);
    if (!buffer)
        return -ENOMEM;

    /* Copy data from iov_iter to buffer */
    if (copy_from_iter(buffer, count, iter) != count) {
        kfree(buffer);
        return -EFAULT;
    }

    mutex_lock(&ei->inode_mutex);

    /* Send PUT request with data */
    memset(&response, 0, sizeof(response));
    ret = kwebdavfs_http_request(fsi, WEBDAV_PUT, ei->url, buffer, count, &response);

    kfree(buffer);

    if (ret < 0) {
        printk(KERN_ERR "kwebdavfs: failed to write %s: %d\n", ei->url, ret);
        goto out_unlock;
    }

    if (response.status_code != 200 && response.status_code != 201) {
        printk(KERN_ERR "kwebdavfs: server returned %d for PUT %s\n", 
               response.status_code, ei->url);
        ret = -EIO;
        goto out_free_response;
    }

    /* Update file size and mtime */
    i_size_write(inode, count);
    inode_set_mtime_to_ts(inode, current_time(inode));
    mark_inode_dirty(inode);

    /* Update ETag if server provided one */
    if (response.etag) {
        kfree(ei->etag);
        ei->etag = kstrdup(response.etag, GFP_KERNEL);
    }

    ret = count;

out_free_response:
    kwebdavfs_free_response(&response);
out_unlock:
    mutex_unlock(&ei->inode_mutex);
    return ret;
}

static int kwebdavfs_file_open(struct inode *inode, struct file *file)
{
    return generic_file_open(inode, file);
}

static int kwebdavfs_file_release(struct inode *inode, struct file *file)
{
    return 0;
}

static loff_t kwebdavfs_file_llseek(struct file *file, loff_t offset, int whence)
{
    return generic_file_llseek(file, offset, whence);
}

const struct file_operations kwebdavfs_file_operations = {
    .owner          = THIS_MODULE,
    .read_iter      = kwebdavfs_file_read_iter,
    .write_iter     = kwebdavfs_file_write_iter,
    .open           = kwebdavfs_file_open,
    .release        = kwebdavfs_file_release,
    .llseek         = kwebdavfs_file_llseek,
};

const struct address_space_operations kwebdavfs_aops = {
    .read_folio     = kwebdavfs_read_folio,
};