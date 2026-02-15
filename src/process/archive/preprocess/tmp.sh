#!/bin/bash

/home/linjk/tools/ida-pro-9.0/idat -A -S"get_strip_code.py" /home/linjk/dataset/cpbcs/bins/vmlinux-4.1.52-x86_O3/vmlinux.elf
/home/linjk/tools/ida-pro-9.0/idat -A -S"get_unstrip_code.py" /home/linjk/dataset/cpbcs/bins/vmlinux-4.1.52-x86_O3/unstrip/vmlinux.elf
/home/linjk/tools/ida-pro-9.0/idat -A -S"get_unstrip_code_fixed.py" /home/linjk/dataset/cpbcs/bins/vmlinux-4.1.52-x86_O3/unstrip/vmlinux.elf