UART Unit Tests
===============

TODO
----
 - Make an example TOML file for each test
 - Perhaps extend descriptions on some of the simpler unit tests

HelloWorld
----------
Test UART DR Write to print "Hello World\n"
 
RxInterrupt
-----------
Test UART Rx Interrupt by receiving user data and issuing simple CLI
 
TxInterrupt
-----------
Test Tx Interrupt. The Tx FIFO should automatically be depleted by streaming
the numbers 0-9. The Tx Interrupt will fire when there are atleast 8 empty
spaces in the Tx FIFO, filling it back up to full with more numbers. 
When the FIFO isn't being filled , the firmware should print the letters a-j
via polling. Additionally, the Rx interrupt is enabled throughout to test 2
interrupts running at the same time. It's the same program as the RxInterrupt
test (simple command line interface)



