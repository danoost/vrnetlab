FROM debian:stable
MAINTAINER Kristian Larsson <kristian@spritelink.net>

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qy \
 && apt-get upgrade -qy \
 && apt-get install -y --no-install-recommends \
    bridge-utils \
    iproute2 \
    python3-ipy \
    socat \
    qemu-kvm \
    qemu-utils \
    wget \
    ca-certificates \
    rpm2cpio \
    cpio \
 && rm -rf /var/lib/apt/lists/*

RUN wget -q -r -np -nH --cut-dirs 3 -e robots=off -A 'edk2.git-ovmf-x64*' https://www.kraxel.org/repos/jenkins/edk2/ \
 && rpm2cpio edk2.git-ovmf-x64*.rpm | cpio -i --make-directories \
 && rm edk2.git-ovmf-x64*.rpm
 
ARG IMAGE
COPY $IMAGE* /
COPY *.py /

EXPOSE 22 80 443 161/udp 830 5000 50051 10000-10099
HEALTHCHECK CMD ["/healthcheck.py"]
ENTRYPOINT ["/launch.py"]
