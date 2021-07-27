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
(For defining generic memory map for ARM cortex-M)
1) ARM Limited. ARM®v7-M Architecture Reference Manual, chapter B3.1.
(For finding NVIC mapped registers in the SCS)
2) ARM Limited. ARM®v7-M Architecture Reference Manual, chapter B3.2.

(For Loading emulator FW from ELF)
1) TIS ELF Specification [ELF Format]https://refspecs.linuxfoundation.org/elf/elf.pdf

(For ARM exceptions and interrupts)
1) Exception Entry and Return [Cortex-M3 User Guide]https://developer.arm.com/documentation/dui0552/a/the-cortex-m3-processor/exception-model/exception-entry-and-return
2) ARM and Thumb Mode [ARM-Thumb Modes]https://www.embedded.com/introduction-to-arm-thumb/


