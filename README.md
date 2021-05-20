Configurable Peripheral Emulator for ARM
========================================

TODO
----

1) Update emulatorSetup.py
   - Get entry and exit points
   - Auto generate mmio for emulatorConfig.toml

2) Create Testing.c/Testing.h files to store functions that test parts of the emulator.

3) Sanity check my UART data structures when they write to memory.
   - Look for other things to sanity check?

4) Get callbacks to know which UART module they are reading.
   - Can scan UART modules for a matching address within the callbacks.
   - Any other ideas?

Projects Referenced or Used
---------------------------
1) Unicorn [Unicorn Github](https://github.com/unicorn-engine/unicorn)
2) P2IM [P2IM Github](https://github.com/RiS3-Lab/p2im)
3) QEMU [QEMU Github](https://github.com/qemu/qemu)
4) TOML [TOML](https://toml.io/en/)  
