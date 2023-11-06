#!/bin/bash

# WARNING. This script will only work on Fedora O/S.

# error announcer. Dump any failure log, then wait forever.
function wait_forever() {
    if [[ "$1" != "" ]] ; then echo "ERROR: ${1}"; fi
    if [[ -f /tmp/log.txt ]] ; then cat /tmp/log.txt ; fi
    echo "Sleeping forever."
    sleep infinity
}

# step 1. Attempt to match the exact host kernel source in the container.
echo "Installing kernel dev pack to match host kernel"
dnf install -y \
    kernel-devel-`uname -r` \
    kernel-core-`uname -r` > /tmp/log.txt 2>&1
if [[ $? != 0 ]] ; then wait_forever "dnf install failed"; fi

# step 2. Compile the kernel module and probe.
echo "Compiling container-ima"
cd /container-integrity-measurement
sed -i "s/^.SECONDARY.*//" Makefile
make > /tmp/log.txt 2>&1
if [[ $? != 0 ]] ; then wait_forever "build failed"; fi

sync
sleep 5
sync

# step 3. Insert the kprobe.
echo "Inserting container-ima kernel module"
insmod ./container_ima.ko > /tmp/log.txt 2>&1
if [[ $? != 0 ]] ; then wait_forever "kernel module insertion failed"; fi

# step 4. Launch the probe.
echo "Launching the ebpf probe"
./probe
if [[ $? != 0 ]] ; then wait_forever "ebpf probe failed"; fi

wait_forever "probe exited"
