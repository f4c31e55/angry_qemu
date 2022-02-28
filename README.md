# angry qemu

<img src="https://angr.io/img/angry_face.png" /><img src="https://gitlab.com/qemu-project/qemu/-/raw/master/ui/icons/qemu.svg" width="187"/>

## Introduction
angry qemu is a tool which allows symbolic execution of the TCG blocks produced by qemu. 

## why?
It was an interesting diversion into the internals of qemu and, to some extent, angr. It should almost certainly not be used for anything real. It is very slow due to reliance on the gdb stub, angr symbolic execution and not being architected for speed. A more sensible solution would likely be to write an angr engine for TCG.

## examples
The tool has been used to solve a few CTF style challenges:
- https://github.com/f4c31e55/writeups/tree/main/hexagon
- https://github.com/f4c31e55/writeups/tree/main/tiamat
- https://github.com/f4c31e55/writeups/tree/main/megaman
