Configurable Peripheral Emulator for ARM
========================================

Version0.0 Details
------------------

1) Automation
   - Python Program does extract ELF info to config file
   - Python Program does NOT automate UART configuration
   
2) Configuration
   - Configuration DOES contain configuration, status, and data registers.
   - Configuration reads firmware, and UART register information.
   - Configuration does NOT read bit configurations or uart_config info.
 
3) Data Structures 
   - Structures DO contain configuration, status, and data registers
   - A structure is setup to contain flag enable information for configuration & status registers.
   
4) Emulation
   - Emulation does NOT generically emulate configuration, status, or data registers.
   - Emulation DOES contain configuration registers.
