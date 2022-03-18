/*
    startup file for cpea unit test firmware
    Defines vector table and Reset_Handler    
*/

#include "startup.h"

/* Vector Table */

// Mark this for the .vector_table section in linker script
__attribute__((section(".vector_table")))

const vector_table_t vectors[] = {
    {.stack_top = &_stack_ptr}, // 0    Pointer to top of Stack
    Reset_Handler,              // 1    Reset handler is called when the <RESET> button is pressed
    NMI_Handler,                // 2    Non-Maskable Interrupt handler
    HardFault_Handler,          // 3    Hard Fault Handler
    MemManageFault_Handler,     // 4    Memory management fault Handler
    BusFault_Handler,           // 5    Bus Fault Handler
    UsageFault_Handler,         // 6    Usage Fault Handler
    0,                          // 7    Reserved
    0,                          // 8    Reserved
    0,                          // 9    Reserved
    0,                          // 10   Reserved
    SVC_Handler,                // 11   SuperVisor Call Handler
    DebugMonitor_Handler,       // 12   Debug Monitor Handler
    0,                          // 13   Reserved
    PendSV_Handler,             // 14   Pendeable interrupt driven request
    SysTick_Handler,            // 15   SysTick Timer handler
    
    /*
        XXX: Many of these ISRs won't be used for individual unit tests
             We keep them all so each unit test shares the same startup file.
    */
          
    UARTrx_ISR,                 // 16   UART receive interrupt service routine
    UARTtx_ISR,                 // 17   UART transmit interrupt service routine        
};

/* ISRs for reset handler and default handler*/

void Reset_Handler(void)
{

    int *src, *dest;
    
    // Copy .data into RAM
    src = &_etext;
    for (dest = &_data; dest < &_edata;)
    {
        *dest++ = *src++;
    }
    
    /* Init .bss values to zero */
    for (dest = &_bss; dest < &_ebss;)
    {
        *dest++ = 0;
    }
    
    // Call main
    main();        
}

void Default_Handler(void)
{
    while(1)
    {
        // Ininfite Loop
    }
}


