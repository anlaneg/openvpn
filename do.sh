#! /bin/bash
aclocal
libtoolize --force
automake --add-missing
autoconf
#sudo apt install libssl-dev liblz4-dev liblzo2-dev  libpam0g-dev
CFLAGS="-g " ./configure
make
