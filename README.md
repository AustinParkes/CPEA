Configurable Peripheral Emulator for ARM
========================================

TODO
----

1) Create Testing.c/Testing.h files to store functions that test parts of the emulator.

2) Sanity check my UART data structures when they write to memory.
   - Look for other things to sanity check?

3) Update emulatorSetup.py
   - Get entry and exit points (exit point can be the function after main() )
   - Auto generate mmio for emulatorConfig.toml

Projects Referenced or Used
---------------------------
1) Unicorn [Unicorn Github](https://github.com/unicorn-engine/unicorn)
2) P2IM [P2IM Github](https://github.com/RiS3-Lab/p2im)
3) QEMU [QEMU Github](https://github.com/qemu/qemu)
4) TOML [TOML](https://toml.io/en/)  
