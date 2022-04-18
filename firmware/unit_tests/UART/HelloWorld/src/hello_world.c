#include <stdio.h>
#include "library.h"

volatile uint32_t * const UARTDR = (uint32_t *)0x4006a007; 


int main(void){
        
    print("Welcome to CPEA!\n", (volatile uint8_t *)UARTDR);            

    return 0;

}

