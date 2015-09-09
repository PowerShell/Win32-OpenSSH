autoreconf
./configure --build=i686-pc-mingw32 --host=i686-pc-mingw32 --with-ssl-dir=../openssl-1.0.1e  --with-kerberos5 --with-zlib=../zlib-1.2.8
cat config.h.tail >> config.h

make ssh.exe
make sshd.exe
make sftp.exe
make sftp-server.exe
make ssh-agent.exe