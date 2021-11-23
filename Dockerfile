FROM fedora:33

WORKDIR /app/fuse-overlayfs
RUN dnf update -y && \
    dnf install -y fuse3-devel leveldb-devel make automake autoconf gcc 

COPY . /app/fuse-overlayfs

RUN sh autogen.sh && \
    LIBS="-ldl" ./configure --prefix /usr && \
    make

CMD ["./fuse-overlayfs","-f"]
