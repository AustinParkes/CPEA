#include <stdio.h>
#include <stdint.h>

// Declare all USART registers
// Handle can be applied to all USART
typedef struct usart{
	uint32_t CR1;
	uint32_t CR2;
	uint32_t CR3;
	uint32_t BRR;
	uint32_t GTPR;
	uint32_t RTOR;
	uint32_t RQR;
	uint32_t ISR;
	uint32_t ICR;
	uint32_t RDR;
	uint32_t TDR;
} USART_handle;

// USART1 address
USART_handle *USART1 = (USART_handle *)0x40013800;

// Function definitions
void USART_Init(USART_handle * USARTx){
	// Disable UART (Set status in emulator for disabling)
	USARTx->CR1 &= 0xFFFFFFFE;  	// Clear bit 0
	
	// Set data Length to 7 bits (bit 28 and 12 only write when UART disabled)
	// 00 = 8 data bits,	01 = 9 data bits, 10 = 7 data bits
	USARTx->CR1 |= 0x10000000; 		// Set bit 28 
	USARTx->CR1 &= 0xFFFFEFFF;     	// Clear bit 12
	
	// Select 1 stop bit (bit13:12 only written when USART disabled)
	// 00 = 1 stop bit			01 = 0.5 stop bit
	// 10 = 2 stop bit          11 = 1.5 stop bit
	USARTx->CR2 &= 0xFFFFCFFF;     	// Clear bits 13:12
	
	// Set no parity (Only written when USART disabled)
	USARTx->CR1 &= 0xFFFFFBFF;     	// Clear bit 10
	
	// Oversample by 16 (Can only be set when USART is disabled)
	USARTx->CR1 &= 0xFFFF7FFF;     	// Clear bit 15
	
	// Set Baud rate to 9600 using APB frequency (80Mhz) ()
	// example 1 in section 22.1.2 for reference
	USARTx->BRR = 0x208D;
	
	// Enable transmission and reception
	// Does this set a status register flag??? check the status register in reference manual
	USARTx->CR1 |= 0x0000000C;		// Enable bits 3:2
	
	// Enable USART
	USARTx->CR1 |= 0x00000001;  	// Set bit 0
	
	// Verify that USART is ready for transmission
	/* Simple implmentation:
	   Set when TE is set
	   Cleared when TE is cleared
	   These flags are set/cleared immediately so the check below will never have to wait for hardware to set the flags
	*/
	
	// TEACK: Trans enable ack flag.
	while((USARTx->ISR & 0x00200000) == 0);  // Check bit 21
	
	// Verify that USART is ready for reception
	// REACK: Rec enable ack flag.
	while((USARTx->ISR & 0x00400000) == 0);  // Check bit 22
	
}

void USART_Read(USART_handle * USARTx, uint8_t *buffer, uint32_t nBytes){
	
	int i;
	
	for(i=0;i < nBytes; i++){
	    // Wait until emulator sets RXNE
		while (!(USARTx->ISR & 0x00000020)); // Check for set bit 5 for RXNE
		buffer[i] = USARTx->RDR;
	}
}

void USART_Write(USART_handle * USARTx, uint8_t *buffer, uint32_t nBytes){
	
	int i;
	
	for(i=0;i<nBytes;i++){
		// Bit 7 set by default in ISR
		while (!(USARTx->ISR & 0x00000080)); // Check for set bit 7 for TXE
		USARTx->TDR = buffer[i] & 0xFF;      // Should clear TXE flag now, cuz not empty 
	}
	// Bit 6 set by default in ISR	
	while (!(USARTx->ISR & 0x00000040));	 // Check if bit 6 is set for TC

	// Set TCCF to clear TC in ICR ... why is this here?
	// Should this be cleared after if you want to continue Tx???
	USARTx->ICR |= 0x00000040;               // Set bit 6
}
	
int main(void){
	// Would normally enable clocks for UART here
	// Would normally select system clock for UART here
	
	uint8_t buf[10];
	
	USART_Init(USART1);
	USART_Read(USART1, buf, 10);
	USART_Write(USART1, buf, 10);
	
	return 0;
}





