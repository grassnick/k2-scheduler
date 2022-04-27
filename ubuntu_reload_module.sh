#!/bin/bash

echo "none" | sudo tee /sys/class/block/nvme0n1/queue/scheduler ;\
    sudo modprobe -r k2_legacy ;\
    sudo mkdir -p /usr/src/k2_legacy-0.0.1/
    sudo cp k2.c Makefile dkms.conf /usr/src/k2_legacy-0.0.1/ &&\
    sudo dkms remove k2_legacy/0.0.1 ;\
    sudo dkms install --force k2_legacy/0.0.1 &&\
    sudo modprobe k2_legacy &&\
    echo "k2_legacy" | sudo tee /sys/class/block/nvme0n1/queue/scheduler


