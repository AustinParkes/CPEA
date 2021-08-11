Configurable Peripheral Emulator for ARM
========================================

Version0.2 Details
----

1. Automation
   - Python program CAN extract ELF info to config file
   - Python program DOES generate raw executable binary "firmware.bin"
   - Python program DOES automate peripheral modules and register counts
     
2. Configuration
   - Configuration ONLY contains status and data registers.
   - Configuration CAN read all peripherals
   
3. Data Structures
   - Structures ONLY contain status and data registers
   - Structure ALLOWS for 8/16/32 bit registers by using arrays to store address/reset values
   - Structure tailored for all peripherals

4. Emulation
   - Emulation DOES generically emulate any peripherals via correct SR values.
   - Emulation does NOT contain configuration registers. (ONLY SR and DR)
   
5. Next Version Goals
   - Integrate this into QEMU. Drop Unicorn. 
   - Add more peripherals to configuration (in Python script and config)
   - Add more SR flags for each peripheral
 
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
(For defining generic memory map for ARM cortex-M)
1) ARM Limited. ARM®v7-M Architecture Reference Manual, chapter B3.1.
(For finding NVIC mapped registers in the SCS)
2) ARM Limited. ARM®v7-M Architecture Reference Manual, chapter B3.2.

(For Loading emulator FW from ELF)
1) TIS ELF Specification [ELF Format]https://refspecs.linuxfoundation.org/elf/elf.pdf

(For ARM exceptions and interrupts)
1) Exception Entry and Return [Cortex-M3 User Guide]https://developer.arm.com/documentation/dui0552/a/the-cortex-m3-processor/exception-model/exception-entry-and-return
2) ARM and Thumb Mode [ARM-Thumb Modes]https://www.embedded.com/introduction-to-arm-thumb/


