Configurable Peripheral Emulator for ARM
========================================

TODO
----

1) Testing Firmware
   - Research firmware samples to test
   - When testing, find out
      1) What needs to be added to emulator
      2) What needs to be added to configuration
      3) What can we automate to make user's life easier
           
2) Add some debugging option for following execution of code (is gdb an option?)  
      
      
DONE
----

1) Callbacks
   - Got rid of UART specific callbacks. Doing callbacks for entire ARM mmio range.
   
2) Automation
   - Generates mmio for emulatorConfig.toml
   
3) Configuration
   - Parses emulatorConfig.toml and stores to appropriate data structure/emulator memory   
         

Projects Referenced or Used
---------------------------
1) Unicorn [Unicorn Github](https://github.com/unicorn-engine/unicorn)
2) P2IM [P2IM Github](https://github.com/RiS3-Lab/p2im)
3) QEMU [QEMU Github](https://github.com/qemu/qemu)
4) TOML [TOML](https://toml.io/en/)  

Code Referenced or Used
-----------------------
1) RIOT Console FW (P2IM used this) [Console]https://github.com/RIOT-OS/RIOT/tree/master/examples/default

Other References
----------------
(For defining Flash and SRAM memory map for Cortex-M Devices)
1) Cortex-M0+ Generic User Guide [M0+ Memory Model]https://developer.arm.com/documentation/dui0662/b/The-Cortex-M0--Processor/Memory-model?lang=en
2) Cortex-M3 Generic User Guide [M3 Memory Model]https://developer.arm.com/documentation/dui0552/a/the-cortex-m3-processor/memory-model
3) Cortex-M4 Generic User Guide [M4 Memory Model]https://developer.arm.com/documentation/dui0553/latest/
4) Cortex-M7 Generic User Guide [M7 Memory Model]https://developer.arm.com/documentation/dui0646/c/the-cortex-m7-processor/memory-model
5) Cortex-M23 Generic User Guide [M23 Memory Model]https://developer.arm.com/documentation/dui1095/a/The-Cortex-M23-Processor/Memory-model
6) Cortex-M33 Generic User Guide [M33 Memory Model]https://developer.arm.com/documentation/100235/0100/The-Cortex-M33-Processor/Memory-model
7) Cortex-M55 Generic User Guide [M55 Memory Model]https://developer.arm.com/documentation/101273/r0p2/The-Cortex-M55-Processor--Reference-Material/Memory-model

(For Loading emulator FW from ELF)
1) TIS ELF Specification [ELF Format]https://refspecs.linuxfoundation.org/elf/elf.pdf

