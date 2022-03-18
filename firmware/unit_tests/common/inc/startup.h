#ifndef STARTUP_H_
#define STARTUP_H_
/*
    startup header file for cpea unit test firmware
    Defines vector table handlers and ISRs
    Declares external variables
*/

typedef void (*element_t)(void);

// Define type for vector table
typedef union {
    element_t isr;
    void *stack_top;
} vector_table_t;

/* Exception Handler Prototypes */

// Default handler, does nothing
void Default_Handler(void);

// System Exceptions
void Reset_Handler(void);
__attribute__((weak, alias("Default_Handler"))) void NMI_Handler(void);
__attribute__((weak, alias("Default_Handler"))) void SVC_Handler(void);
__attribute__((weak, alias("Default_Handler"))) void DebugMonitor_Handler(void);
__attribute__((weak, alias("Default_Handler"))) void PendSV_Handler(void);
__attribute__((weak, alias("Default_Handler"))) void SysTick_Handler(void);

// Fault Handlers
__attribute__((weak, alias("Default_Handler"))) void HardFault_Handler(void);
__attribute__((weak, alias("Default_Handler"))) void MemManageFault_Handler(void);
__attribute__((weak, alias("Default_Handler"))) void BusFault_Handler(void);
__attribute__((weak, alias("Default_Handler"))) void UsageFault_Handler(void);

/* Interrupt Service Routine Prototypes */
__attribute__((weak, alias("Default_Handler"))) void UARTrx_ISR(void);
__attribute__((weak, alias("Default_Handler"))) void UARTtx_ISR(void);

/* External Variable Declarations */
extern int main(void);

//stack pointer
extern int _stack_ptr;

//.text/code,stored in Flash
extern int _etext;

//.data,copied into RAM on boot
extern int _data;
extern int _edata;

//.bss,unitialized variables
extern int _bss;
extern int _ebss;

#endif
