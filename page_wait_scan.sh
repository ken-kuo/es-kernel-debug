#!/bin/bash
insmod es_debug.ko
echo 12 > /sys/kernel/debug/es_debug/test
rmmod es_debug
dmesg |tail -n 30 > es_debug.log
