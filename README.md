Configurable Peripheral Emulator for ARM
========================================

TODO
----

1) Finish making UART register configurations generic.
   1) Go through ref manual and find max number of CR, SR, DR that may exist.
      - Update TOML with these generic registers.

1) Find a way for user map bit functionality to certain registers.
   1) Go through reference manuals and 
   2) Determine the bit functionalities that we care about.
      - CR bit, Does it affect status register? If so, which SR bit does it affect?     
      - SR bit, What CR bits affect this SR bit?
      
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
