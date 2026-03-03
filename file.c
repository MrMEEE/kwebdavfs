#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/buffer_head.h>
#include <linux/vmalloc.h>
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

/*
 * Flush the write buffer to the server with a single PUT.
 * Caller must hold ei->inode_mutex.
 */
static int kwebdavfs_flush_write_buf(struct inode *inode)
{
    struct kwebdavfs_inode_info *ei = KWEBDAVFS_I(inode);
    struct kwebdavfs_fs_info *fsi = KWEBDAVFS_SB(inode->i_sb);
    struct webdav_response resp;
    int ret;

    if (!ei->write_dirty || !ei->write_buf)
        return 0;

    memset(&resp, 0, sizeof(resp));
    ret = kwebdavfs_http_request(fsi, WEBDAV_PUT, ei->url,
                                 ei->write_buf, ei->write_buf_len, &resp);
    if (ret == 0 && resp.status_code != 200 &&
        resp.status_code != 201 && resp.status_code != 204) {
        printk(KERN_ERR "kwebdavfs: PUT %s returned %d\n",
               ei->url, resp.status_code);
        ret = -EIO;
    }
    if (ret == 0) {
        ei->write_dirty = false;
        i_size_write(inode, ei->write_buf_len);
        ei->remote_size = ei->write_buf_len;
        /* free buffer after flush — next open will re-GET if needed */
        kvfree(ei->write_buf);
        ei->write_buf       = NULL;
        ei->write_buf_alloc = 0;
        ei->write_buf_len   = 0;
        if (resp.etag) {
            kfree(ei->etag);
            ei->etag = kstrdup(resp.etag, GFP_KERNEL);
        }
        inode_set_mtime_to_ts(inode, current_time(inode));
        mark_inode_dirty(inode);
    }
    kwebdavfs_free_response(&resp);
    return ret;
}

static ssize_t kwebdavfs_file_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
    struct file *file = iocb->ki_filp;
    struct inode *inode = file_inode(file);
    struct kwebdavfs_inode_info *ei = KWEBDAVFS_I(inode);
    struct kwebdavfs_fs_info *fsi = KWEBDAVFS_SB(inode->i_sb);
    size_t count = iov_iter_count(iter);
    loff_t offset = iocb->ki_pos;
    size_t new_len;
    int ret = 0;

    if (!ei->url)
        return -ENOENT;
    if (count == 0)
        return 0;

    mutex_lock(&ei->inode_mutex);

    /* Logical size after this write */
    new_len = (size_t)max_t(loff_t,
                            (loff_t)ei->write_buf_len,
                            (loff_t)(offset + count));

    /* Grow or allocate the write buffer */
    if (!ei->write_buf || new_len > ei->write_buf_alloc) {
        size_t new_alloc = max(new_len, ei->write_buf_alloc * 2);
        char *newbuf = kvzalloc(new_alloc, GFP_KERNEL);
        if (!newbuf) {
            ret = -ENOMEM;
            goto out_unlock;
        }

        if (ei->write_buf) {
            /* Already have buffered data — extend it */
            memcpy(newbuf, ei->write_buf, ei->write_buf_len);
            kvfree(ei->write_buf);
        } else {
            /* First write to this open file */
            loff_t cur_size = i_size_read(inode);
            if (cur_size > 0 && (offset > 0 || (loff_t)count < cur_size)) {
                /* Partial write: need existing content from server */
                struct webdav_response get_resp;
                memset(&get_resp, 0, sizeof(get_resp));
                ret = kwebdavfs_http_request(fsi, WEBDAV_GET, ei->url,
                                             NULL, 0, &get_resp);
                if (ret == 0 && get_resp.data && get_resp.data_len > 0)
                    memcpy(newbuf, get_resp.data,
                           min_t(size_t, get_resp.data_len, new_alloc));
                kwebdavfs_free_response(&get_resp);
                if (ret < 0) {
                    kvfree(newbuf);
                    goto out_unlock;
                }
            }
        }
        ei->write_buf       = newbuf;
        ei->write_buf_alloc = new_alloc;
    }

    /* Copy caller data into the buffer */
    if (copy_from_iter(ei->write_buf + offset, count, iter) != count) {
        ret = -EFAULT;
        goto out_unlock;
    }

    ei->write_buf_len = new_len;
    ei->write_dirty   = true;
    i_size_write(inode, new_len);
    iocb->ki_pos = offset + count;
    ret = count;

out_unlock:
    mutex_unlock(&ei->inode_mutex);
    return ret;
}

static int kwebdavfs_file_open(struct inode *inode, struct file *file)
{
    return generic_file_open(inode, file);
}

static int kwebdavfs_file_fsync(struct file *file, loff_t start, loff_t end,
                                int datasync)
{
    struct inode *inode = file_inode(file);
    struct kwebdavfs_inode_info *ei = KWEBDAVFS_I(inode);
    int ret;

    mutex_lock(&ei->inode_mutex);
    ret = kwebdavfs_flush_write_buf(inode);
    mutex_unlock(&ei->inode_mutex);
    return ret;
}

static int kwebdavfs_file_release(struct inode *inode, struct file *file)
{
    struct kwebdavfs_inode_info *ei = KWEBDAVFS_I(inode);
    int ret;

    mutex_lock(&ei->inode_mutex);
    ret = kwebdavfs_flush_write_buf(inode);  /* safety flush if fsync was skipped */
    mutex_unlock(&ei->inode_mutex);
    if (ret < 0)
        printk(KERN_ERR "kwebdavfs: flush on close failed for %s: %d\n",
               ei->url, ret);
    return 0;  /* never fail release — data is best-effort at this point */
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
    .fsync          = kwebdavfs_file_fsync,
    .llseek         = kwebdavfs_file_llseek,
};

const struct address_space_operations kwebdavfs_aops = {
    .read_folio     = kwebdavfs_read_folio,
};