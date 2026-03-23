#!/bin/bash

i686-w64-mingw32-gcc -c cs_veeam_dumper.c -o cs_veeam_dumper.x86.o
x86_64-w64-mingw32-gcc -c cs_veeam_dumper.c -o cs_veeam_dumper.x64.o