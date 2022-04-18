#include <stdio.h>
#include "library.h"
#include "RxInterrupt.h"

#define CMD_MAX_LEN 20

enum State state;

UART0regs UART0 = {
    .CR2 = (uint8_t *)0x4006A003,
    .SR1 = (uint8_t *)0x4006A004,
    .DR = (uint8_t *)0x4006A007,
    .CR7 = (uint8_t *)0x4006A015
};

int read;
char command[CMD_MAX_LEN];

int main(void){
        
    print("RxInterrupt Test!\n", UART0.DR);            
    enable_irqs();
    
    // Enable Rx Interrupt
    SET_BIT(*UART0.CR2, 5);
    
    // FIFO threshold to trigger interrupt
    *UART0.CR7 = 1;     
    
    read = 0;
    cp_memset(command, '\0', CMD_MAX_LEN);
        
    state = PROMPT;
    while (1){   
        switch (state){
        case IDLE:          /* Wait for interrupt */
            break;
            
        case PROMPT:        /* Input is ready */
            print("> ", UART0.DR);
            state = IDLE;        
            break;
            
        case RXINTR:        /* Rx Interrupt occurred */  
            
            state = IDLE;             
            if (command[read] == '\n' || command[read] == '\r'){
                            
                // XXX: As long as first 4 letters are "help", print message
                if (!cp_strncmp(command, "help", 4)){
                    print_cmd(command, UART0.DR);
                    print("help is the only command!\n", UART0.DR);                   
                    state = PROMPT;     
                }
                else{
                    print_cmd(command, UART0.DR);                
                    print("Invalid Command. \"help\" is the only valid command!\n", UART0.DR);
                    state = PROMPT;
                }
                read = 0;
                cp_memset(command, '\0', CMD_MAX_LEN);            
            } 
            
            else{
                read++;                
                // Reserve 20th byte as '0'       
                if (read == 19){
                    print("Command Buffer Reached. Resetting\n", UART0.DR);
                    state = PROMPT;
                    cp_memset(command, '\0', CMD_MAX_LEN);
                    read = 0;
                }
            }     
            break;
        
        default:
            break;        
        }
    }

    return 0;

}

void UARTrx_ISR(void){
    // Read a byte from DR if flag is set
    if (CHECK_BIT(*UART0.SR1, 5)){
        command[read] = *UART0.DR;      
        state = RXINTR;        
    } 
}


