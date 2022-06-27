#!/bin/bash

echo "none" | sudo tee /sys/class/block/nvme0n1/queue/scheduler ;\
    sudo modprobe -r k2 ;\
    sudo mkdir -p /usr/src/k2-0.0.2/
    sudo cp k2.c k2.h Makefile dkms.conf k2_trace.h ringbuf.h dkms_pre_build.sh /usr/src/k2-0.0.2/ &&\
    sudo dkms remove k2/0.0.2 ;\
    sudo dkms install --force k2/0.0.2 &&\
    sudo modprobe k2 &&\
    echo "k2" | sudo tee /sys/class/block/nvme0n1/queue/scheduler


