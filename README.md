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
