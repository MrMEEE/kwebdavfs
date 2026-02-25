savedcmd_kwebdavfs.mod := printf '%s\n'   main.o super.o inode.o dir.o file.o http.o tls.o | awk '!x[$$0]++ { print("./"$$0) }' > kwebdavfs.mod
