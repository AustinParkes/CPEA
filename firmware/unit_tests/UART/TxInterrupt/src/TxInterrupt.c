#include <stdio.h>
#include "library.h"
#include "TxInterrupt.h"

#define CMD_MAX_LEN 20

enum State state;

UART0regs UART0 = {
    .CR2 = (uint8_t *)0x4006A003,   /* Interrupt Enable */
    .SR1 = (uint8_t *)0x4006A004,   /* Interrupt Flags  */
    .DR = (uint8_t *)0x4006A007,
    .CR6 = (uint8_t *)0x4006A013,   /* Tx Watermark     */
    .FTC  = (uint8_t *)0x4006A014,  /* FIFO Tx Count    */
    .CR7 = (uint8_t *)0x4006A015,   /* Rx Watermark     */
    .ICR = (uint8_t *)0x4006A020,   /* Interrupt Clear  */
    .FSZ = (uint8_t *)0x4006A021,   /* Tx FIFO Size     */
    .TFF = (uint8_t *)0x4006A022    /* Tx FIFO Full     */
};

int read;
char command[CMD_MAX_LEN];

const char *StreamStart;
const char *TxStream = "0123456789\n";

const char *PollStart;
const char *TxPoll   = "abcdefghij\n";

/*
    RxInterrupt Enable: CR2, bit 5
    RxInterrupt Flag:   SR1, bit 5 

    TxInterrupt Enable: CR2, bit 7
    TxInterrupt Flag:   SR1, bit 7    
*/

int main(void){
        
    print("TxInterrupt Test!\n", UART0.DR);           
    enable_irqs();    
    
    SET_BIT(*UART0.CR2, 5);         // Enable Rx Interrupt ((Via FIFO trigger))  
    *UART0.CR7 = 1;                 // Rx FIFO threshold to trigger interrupt (1 full)     
  
    SET_BIT(*UART0.CR2, 7);         // Enable Tx Interrupt (Via FIFO trigger)   
    *UART0.CR6 = 8;                 // Tx FIFO threshold to trigger interrupt (8 empty)
    
    StreamStart = TxStream;
    PollStart = TxPoll;

    read = 0;
    cp_memset(command, '\0', CMD_MAX_LEN);
            
    state = POLL;
    while (1){   
        switch (state){
        case POLL:          /* Print a-j via Polling OR Wait for Rx interrupt */
        
            // Dead loop so FW doesn't execute at a blazing speed
            cp_wait(1000);
        
            if (*TxPoll == '\0')
                TxPoll = PollStart;
            print_char(*TxPoll, UART0.DR);
            TxPoll++;
            break;
            
        case RXINTR:        /* Rx Interrupt occurred */  
            
            state = POLL;             
            if (command[read] == '\n' || command[read] == '\r'){
                            
                // XXX: As long as first 4 letters are "help", print message
                if (!cp_strncmp(command, "help", 4)){
                    print_cmd(command, UART0.DR);
                    print("help is the only command!\n", UART0.DR);                       
                }
                else{
                    print_cmd(command, UART0.DR);                
                    print("Invalid Command. \"help\" is the only valid command!\n", UART0.DR);
                }
                read = 0;
                cp_memset(command, '\0', CMD_MAX_LEN);            
            } 
            
            else{
                read++;                     
                if (read == 19){
                    print("Command Buffer Reached. Resetting\n", UART0.DR);
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


void UARTtx_ISR(void){
    
    /* 
        Fill Tx FIFO completely
    */   
    
    // XXX: Test FIFO count and FIFO Size registers    
    if (CHECK_BIT(*UART0.SR1, 7)){
        while (*UART0.FTC < *UART0.FSZ){
            if (*TxStream == '\0')   
                TxStream = StreamStart; 
                                          
            *UART0.DR = *TxStream;
            TxStream++; 
        }                
       
        // Clear Tx Interrupt when finished
        SET_BIT(*UART0.ICR, 7);            
    }    
    

    // XXX: Test FIFO Full flag when it's set/cleared
    /*
    if (CHECK_BIT(*UART0.SR1, 7)){
        while (!(CHECK_BIT(*UART0.TFF, 7))){        // FIFO Full when set
        //while ((CHECK_BIT(*UART0.TFF, 7))){        // FIFO Full when cleared 
            if (*TxStream == '\0')   
                TxStream = StreamStart; 
                                          
            *UART0.DR = *TxStream;
            TxStream++; 
        }                
        // Clear Tx Interrupt when finished
        SET_BIT(*UART0.ICR, 7);            
    }
    */
  
}

