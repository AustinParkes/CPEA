Configurable Peripheral Emulator for ARM
========================================

Version0.1 Details
----

1. Automation
   - Python Program DOES extract ELF info to config file
   - Python Program DOES automate peripheral modules and register counts
     
2. Configuration
   - Configuration ONLY contains status and data registers.
   - Configuration DOES read firmware information
   - Configuration ONLY reads UART peripheral.
   
   
3. Data Structures
   - Structures ONLY contain status and data registers
   - Structure ALLOWS for 8/16/32 bit registers by using arrays to store address/reset values
   - Structure ONLY tailored for UART and NOT for all peripherals.

4. Emulation
   - Emulation does NOT generically emulate any peripherals. Only Data registers.
   - Emulation does NOT contain configuration registers. (ONLY SR and DR)
   
5. Next Version Goals
   - Make data structures/emulator more generic for ANY peripheral. Not just UART.
   - Add more peripherals to configuration
   - Add more SR flags for each peripheral
   - Research interrupt support   

Projects Referenced or Used
---------------------------
1) Unicorn [Unicorn Github](https://github.com/unicorn-engine/unicorn)
2) P2IM [P2IM Github](https://github.com/RiS3-Lab/p2im)
3) QEMU [QEMU Github](https://github.com/qemu/qemu)
4) TOML [TOML](https://toml.io/en/)  
