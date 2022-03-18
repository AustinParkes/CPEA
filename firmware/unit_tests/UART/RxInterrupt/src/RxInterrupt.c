#include <stdio.h>
#include <string.h>
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
        
    print("RxInterrupt Test!\n");            
    enable_irqs();
    
    // Enable Rx Interrupt
    SET_BIT(*UART0.CR2, 5);
    
    // FIFO threshold to trigger interrupt
    *UART0.CR7 = 1;     
    
    read = 0;
    cp_memset(command, 0, CMD_MAX_LEN);
        
    state = PROMPT;
    while (1){   
        switch (state){
        case IDLE:          /* Wait for interrupt */
            break;
            
        case PROMPT:        /* Input is ready */
            print("> ");
            state = IDLE;        
            break;
            
        case RXINTR:        /* Rx Interrupt occurred */  
            
            state = IDLE;             
            if (command[read] == '\n' || command[read] == '\r'){
                            
                // XXX: As long as first 4 letters are "help", print message
                if (!cp_strncmp(command, "help", 4)){
                    print_cmd();
                    print("help is the only command!\n");                   
                    state = PROMPT;     
                }
                else{
                    print_cmd();                
                    print("Invalid Command. \"help\" is the only valid command!\n");
                    state = PROMPT;
                }
                read = 0;
                cp_memset(command, 0, CMD_MAX_LEN);            
            } 
            
            else{
                read++;                
                // Reserve 20th byte as '0'       
                if (read == 19){
                    print("Command Buffer Reached. Resetting\n");
                    state = PROMPT;
                    cp_memset(command, 0, CMD_MAX_LEN);
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

void cp_memset(char *src, int c, int size){

    int i;    
    for (i = 0; i < size; i++){
        *src = (unsigned char)c;
        *src++;
    }
}

int cp_strncmp(const char *str1, const char *str2, int n){

    int i;
    
    for (i = 0; i < n; i++){
        if (*str1 == *str2){
            str1++;
            str2++;
        }
                
        // Failure
        else
            return 1;
    }
    
    return 0;    
}

void print_char(uint8_t c){
    *UART0.DR = (uint32_t)c;
}

void print(const char *s){
    while (*s != '\0'){
        *UART0.DR = (uint32_t)(*s);
        s++;
    }
}

void print_cmd(void){
    int c = 0;
    while (command[c] != 0){
        print_char(command[c]);
        c++;
    }
    print("\n");
}

void enable_irqs(void){

    uint32_t const *NVIC_ISER_START = (uint32_t *)0xE000E100;
    uint32_t const *NVIC_ISER_END = (uint32_t *)0xE000E11C;
    
    uint32_t *NVIC_PTR = (uint32_t *)NVIC_ISER_START;
    
    while (NVIC_PTR <= NVIC_ISER_END){
        *NVIC_PTR = (uint32_t)0xFFFFFFFF;
        NVIC_PTR += (uint32_t)4;
    }        
}

void UARTrx_ISR(void){
    // Read a byte from DR if flag is set
    if (CHECK_BIT(*UART0.SR1, 5)){
        command[read] = *UART0.DR;      
        state = RXINTR;        
    } 
}


