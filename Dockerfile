
# Hello there! This challenge uses docker images to help you with our particular infrastructure.

# docker build -t labsec-challenge .

# First, we need to download the Ubuntu docker image.
FROM centos:7
# Here, we are doing some updates, to be safe! Better safe than sorry.
RUN yum -y update

# Let's get it started ...
# We need git to clone our OpenSSL wrapper, the LibcryptoSEC.
# Also, we need wget to dowload a specific version of OpenSSL.
# Finally, gcc, g++, and make to get it done :)
RUN yum -y install git wget gcc g++ make vim libpqxx postgresql-devel
RUN yum -y install gcc gcc-c++ make clang make

# Let's create a safe /home/ to go. It is not a proper user, it is just a folder.
RUN mkdir /home/labsec/

# Let's install OpenSSL, as you know, OpenSSL is a open source project to use crypto.
# Here, we will download version 1.0.2k and install it in /usr/local/ssl/ in order to not mess with the OS's one. 
RUN cd /home/labsec/ \
    && wget https://www.openssl.org/source/old/1.0.2/openssl-1.0.2k.tar.gz \
    && tar -xvf openssl-1.0.2k.tar.gz \
    && cd openssl-1.0.2k/ \
    && ./config shared -Wl,-rpath -Wl,/usr/local/ssl/lib -L/usr/local/ssl/lib -I/usr/local/ssl/include \
    && make \
    && make install

# Libp11
RUN cd /home/labsec/ \
    && wget https://github.com/OpenSC/libp11/releases/download/libp11-0.4.7/libp11-0.4.7.tar.gz \
    && tar -xvf libp11-0.4.7.tar.gz \
    && cd libp11-0.4.7/ \
    && export OPENSSL_CFLAGS=-I/usr/local/ssl/include \
    && export OPENSSL_LIBS="-Wl,-rpath -Wl,/usr/local/ssl/lib -L/usr/local/ssl/lib -lcrypto -ldl" \
    && ./configure --prefix=/opt/libp11 \
    && make \
    && make install

# And now, LibcryptoSEC.
RUN cd /home/labsec/ \
    && git clone https://github.com/LabSEC/libcryptosec.git \
    && cd libcryptosec/ \
    && export OPENSSL_PREFIX=/usr/local/ssl \
    && export OPENSSL_LIBDIR=$OPENSSL_PREFIX/lib \
    && export LIBP11_PREFIX=/opt/libp11 \
    && export LIBP11_LIBDIR=$LIBP11_PREFIX/lib \
    && make \
    && make install
	
RUN export PKG_CONFIG_PATH=/usr/pgsql-10/lib/pkgconfig

RUN yum -y install epel-release openssh openssh-server
RUN yum -y install libpqxx-devel
RUN echo 'root:root' | chpasswd

RUN mkdir /home/labsec/challenge
