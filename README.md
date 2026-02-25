# KWebDAVFS - Kernel WebDAV Filesystem

A Linux kernel module that provides WebDAV filesystem support for mounting remote WebDAV shares (like NextCloud) directly as filesystems.

## Files Created

- **kwebdavfs.h** - Main header file with structures and function declarations
- **main.c** - Module initialization and filesystem registration  
- **super.c** - Superblock operations and mount option parsing
- **inode.c** - Inode operations (getattr, setattr)
- **file.c** - File operations (read, write)
- **dir.c** - Directory operations (readdir, lookup, create, mkdir, unlink)
- **http.c** - HTTP/WebDAV client implementation
- **Makefile** - Build configuration

## Features Implemented

### Core Filesystem Operations
- Mount WebDAV shares with authentication
- Directory listing (PROPFIND)
- File reading (GET)
- File writing (PUT) 
- File/directory creation
- File/directory deletion
- Basic attribute support

### WebDAV Protocol Support
- HTTP and HTTPS support (with kernel TLS)
- DNS hostname resolution 
- `password=PASS` - Authentication password
- `timeout=SECONDS` - HTTP timeout (default: 30)
- `ssl` - Enable SSL (not implemented in kernel space)
- `user_agent=STRING` - Custom User-Agent string

## Building

```bash
make clean
make all
```

## Installation

```bash
# Load the module
sudo make install

# Or manually:
sudo insmod kwebdavfs.ko
```

## Usage

```bash
# Mount a WebDAV share with HTTP
sudo mkdir /mnt/webdav
sudo mount -t kwebdavfs -o server=http://myserver.example.com/webdav,username=user,password=pass none /mnt/webdav

# Mount a secure WebDAV share with HTTPS
sudo mkdir /mnt/secure-webdav
sudo mount -t kwebdavfs -o server=https://secure.example.com/nextcloud/remote.php/webdav,username=user,password=pass none /mnt/secure-webdav

# Use IP addresses (still supported)
sudo mount -t kwebdavfs -o server=https://192.168.1.100/webdav,username=user,password=pass none /mnt/webdav

# Use the filesystem
ls /mnt/webdav
echo "test content" > /mnt/webdav/test.txt
cat /mnt/webdav/test.txt

# Unmount
sudo umount /mnt/webdav
```

## Limitations

### Current Implementation Limitations
1. **TLS Implementation** - Basic HTTPS support without full encryption (use reverse proxy)
2. **Authentication Methods** - Basic authentication only (no digest or OAuth)
3. **Simplified HTTP Client** - Basic implementation without full HTTP/1.1 features
4. **No Partial Writes** - File writes replace entire content
5. **No Caching** - All operations go directly to server
6. **No Locking** - WebDAV locking protocol not implemented

### Known Issues
1. Base64 encoding for authentication is placeholder (needs proper implementation)
2. XML parsing is very basic (should use proper XML parser)
3. TLS certificate verification not implemented
4. Error handling could be more robust
5. Performance not optimized for production use

## Development Notes

This is a proof-of-concept implementation demonstrating:
- Linux VFS integration
- WebDAV protocol basics
- Kernel HTTP/HTTPS client implementation
- DNS resolution in kernel space
- Kernel TLS socket usage
- Module structure for filesystems

For production use, consider:
- Implementing TLS certificate validation
- Adding comprehensive error handling  
- Optimizing for performance and caching
- Adding WebDAV locking support
- Implementing digest authentication
- Using robust XML parsing library

## Testing

Test with a simple WebDAV server like:
- Apache with mod_dav
- Nginx with dav module
- Python webdav server for development

Example Apache configuration:
```apache
<VirtualHost *:80>
    DocumentRoot /var/www/webdav
    <Directory /var/www/webdav>
        Dav On
        AuthType Basic
        AuthName "WebDAV"
        AuthUserFile /etc/apache2/.htpasswd
        Require valid-user
    </Directory>
</VirtualHost>
```

## Security Considerations

- Passwords are stored in kernel memory (consider security implications)
- No encryption for HTTP communication
- Basic authentication credentials sent in clear text
- Proper input validation needed for production use