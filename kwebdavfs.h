#ifndef _KWEBDAVFS_H
#define _KWEBDAVFS_H

#include <linux/fs.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>

#define KWEBDAVFS_MAGIC     0x57454244  /* "WEBD" */
#define KWEBDAVFS_VERSION   "1.0"

/* Forward declarations */
struct kwebdavfs_fs_info;
struct kwebdavfs_inode_info;

/* Filesystem info structure - mounted per filesystem */
struct kwebdavfs_fs_info {
    char *server_url;        /* WebDAV server URL (full, e.g. https://host/dav/path/) */
    char *base_url;          /* Scheme+host only, e.g. https://host (for PROPFIND hrefs) */
    char *username;          /* Authentication username */
    char *password;          /* Authentication password */
    char *user_agent;        /* HTTP User-Agent string */
    unsigned int timeout;     /* HTTP timeout in seconds */
    bool use_ssl;            /* Use HTTPS */
    bool verify_ssl;         /* Verify SSL certificates */
    kuid_t uid;              /* Default file owner UID */
    kgid_t gid;              /* Default file group GID */
    unsigned long dir_ttl_jiffies; /* Dir cache TTL; 0 = write-invalidation only */
    struct mutex fs_mutex;   /* Filesystem-wide mutex */
};

/* Per-inode info structure */
struct kwebdavfs_inode_info {
    struct inode vfs_inode;         /* Must be first */
    char *url;                      /* Full WebDAV URL for this file/dir */
    char *etag;                     /* HTTP ETag for caching */
    loff_t remote_size;             /* Size reported by server */
    struct timespec64 remote_mtime; /* Modification time from server */
    /* Directory listing cache (populated by readdir, consumed by lookup) */
    struct list_head dir_cache;     /* list of webdav_dirent */
    unsigned long dir_cache_until;  /* jiffies: dir cache valid until this */
    struct mutex inode_mutex;       /* Per-inode mutex */
};

/* Directory cache TTL: 5 minutes (safety net for external changes).
 * The cache is also invalidated immediately on any local write (create,
 * unlink, mkdir, rmdir), so local changes are always visible instantly. */
#define KWEBDAVFS_DIR_TTL_DEFAULT_SECS  300

/* HTTP request types */
enum webdav_method {
    WEBDAV_GET,
    WEBDAV_PUT,
    WEBDAV_PROPFIND,
    WEBDAV_PROPPATCH,
    WEBDAV_MKCOL,
    WEBDAV_DELETE,
    WEBDAV_COPY,
    WEBDAV_MOVE,
    WEBDAV_HEAD,
    WEBDAV_OPTIONS
};

/* HTTP response structure */
struct webdav_response {
    int status_code;
    char *data;
    size_t data_len;
    char *etag;
    loff_t content_length;
    struct timespec64 last_modified;
};

/* Directory entry for PROPFIND responses */
struct webdav_dirent {
    char *name;
    char *href;
    bool is_dir;
    loff_t size;
    struct timespec64 mtime;
    char *etag;
    struct list_head list;
};

/* Inline functions to get our structs from VFS structs */
static inline struct kwebdavfs_inode_info *KWEBDAVFS_I(struct inode *inode)
{
    return container_of(inode, struct kwebdavfs_inode_info, vfs_inode);
}

static inline struct kwebdavfs_fs_info *KWEBDAVFS_SB(struct super_block *sb)
{
    return sb->s_fs_info;
}

/* Function declarations */

/* super.c */
int kwebdavfs_parse_options(struct kwebdavfs_fs_info *fsi, char *options);
struct inode *kwebdavfs_get_root_inode(struct super_block *sb);

/* inode.c */
struct inode *kwebdavfs_get_inode(struct super_block *sb, const struct inode *dir,
                                  umode_t mode, dev_t dev, const char *url);
struct inode *kwebdavfs_iget(struct super_block *sb, const char *url);
int kwebdavfs_getattr(struct mnt_idmap *idmap, const struct path *path,
                      struct kstat *stat, u32 request_mask, unsigned int flags);
int kwebdavfs_setattr(struct mnt_idmap *idmap, struct dentry *dentry,
                      struct iattr *iattr);

/* file.c */
extern const struct file_operations kwebdavfs_file_operations;
extern const struct inode_operations kwebdavfs_file_inode_operations;
extern const struct address_space_operations kwebdavfs_aops;

/* dir.c */
extern const struct file_operations kwebdavfs_dir_operations;
extern const struct inode_operations kwebdavfs_dir_inode_operations;

/* http.c */
int kwebdavfs_http_init(void);
void kwebdavfs_http_exit(void);
int kwebdavfs_http_request(struct kwebdavfs_fs_info *fsi, enum webdav_method method,
                          const char *url, const char *body, size_t body_len,
                          struct webdav_response *response);
int kwebdavfs_http_move(struct kwebdavfs_fs_info *fsi, const char *src_url,
                        const char *dst_url, bool overwrite);
int kwebdavfs_propfind(struct kwebdavfs_fs_info *fsi, const char *url,
                      struct list_head *entries);
void kwebdavfs_free_dirents(struct list_head *entries);
void kwebdavfs_free_response(struct webdav_response *response);

/* Utility functions */
char *kwebdavfs_url_encode_segment(const char *name);
char *kwebdavfs_build_url(struct kwebdavfs_fs_info *fsi, const char *path);
/* Convert a PROPFIND href (absolute path like /dav/files/mjp/foo) to a full URL */
char *kwebdavfs_href_to_url(struct kwebdavfs_fs_info *fsi, const char *href);
int kwebdavfs_parse_xml_response(const char *xml, const char *request_url, struct list_head *entries);

#endif /* _KWEBDAVFS_H */