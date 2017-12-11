#!/bin/bash
insmod es_debug.ko
echo 15 > /sys/kernel/debug/es_debug/test
rmmod es_debug
