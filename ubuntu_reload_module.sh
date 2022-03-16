#!/bin/bash

echo "none" | sudo tee /sys/class/block/nvme0n1/queue/scheduler ;\
    sudo modprobe -r k2 ;\
    sudo cp k2.c k2.h Makefile dkms.conf k2_trace.h /usr/src/k2-0.0.1/ &&\
    sudo install -m 644 k2_trace.h /lib/modules/$(uname -r)/build/include/trace/events/k2.h &&\
    sudo dkms remove k2/0.0.1 ;\
    sudo dkms install --force k2/0.0.1 &&\
    sudo modprobe k2 &&\
    echo "k2" | sudo tee /sys/class/block/nvme0n1/queue/scheduler


