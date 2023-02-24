Configurable Peripheral Emulator for ARM
========================================

Big TODOs
---------
      
      
DONE
----


PROBLEMS
--------
     

Projects Referenced or Used
---------------------------
1) Unicorn [Unicorn Github](https://github.com/unicorn-engine/unicorn)
2) P2IM [P2IM Github](https://github.com/RiS3-Lab/p2im)
3) QEMU [QEMU Github](https://github.com/qemu/qemu)
4) TOML [TOML](https://toml.io/en/)  
5) HALucinator [HALucinator Github](https://github.com/embedded-sec/halucinator)
6) AVATAR2 [AVATAR2 Github](https://github.com/avatartwo/avatar2)

Code Referenced or Used
-----------------------
1) RIOT Console FW (P2IM used this) [Console](https://github.com/RIOT-OS/RIOT/tree/master/examples/default)
2) QEMU PL011 UART by Paul Brook [Prime Cell UART](https://github.com/qemu/qemu/blob/master/hw/char/pl011.c)
3) tm4c-linux-template by shawn-dsliva [MCU Compilation](https://github.com/shawn-dsilva/tm4c-linux-template)

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

