FROM fedora:38
ARG repo=https://github.com/avery-blanchard/container-integrity-measurement
ARG branch=main

# basic pre-reqs
RUN dnf update -y
RUN dnf groupinstall -y "Development Tools" "Development Libraries"

# bpf prereqs
RUN dnf install -y kernel-devel kernel-headers \
    git libbpf libbpf-devel bpftool clang \
    openssl dwarves glibc-devel.i686

# trying to guess the Fedora kernel version.
RUN dnf install -y \
    kernel-devel-6.2.9-300.fc38 \
    kernel-core-6.2.9-300.fc38


RUN cd / && git clone ${repo} -b ${branch} /container-integrity-measurement
RUN cd /container-integrity-measurement && git submodule update --init --recursive

COPY run_fedora.sh /run_fedora.sh
CMD /run_fedora.sh
