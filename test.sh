#!/bin/bash
insmod es_debug.ko
echo 18 > /sys/kernel/debug/es_debug/test
rmmod es_debug
