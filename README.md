Configurable Peripheral Emulator for ARM
========================================

Big TODOs
---------

1) Integrate Unique Code with QEMU.

2) Debug Interface 

3) Fuzzing Framework
      
      
DONE
----

1) Callbacks
   - Got rid of UART specific callbacks. Doing callbacks for entire ARM mmio range.
   
2) Automation
   - Generates mmio for emulatorConfig.toml
   
3) Configuration
   - Parses emulatorConfig.toml and stores to appropriate data structure/emulator memory   

4) SVC calls and Interrupt Firing (Buggy)

PROBLEMS
--------

1) Don't switch SP context to MSP or PSP when unstacking.

2) Many meticulous hardware pieces missing that QEMU should already have.        

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


