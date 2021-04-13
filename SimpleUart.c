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
USART_handle *USART1 = ((USART_handle *)0x40013800);

// Test if emulator will run functions
void read_DR(){
	uint8_t buf;
	buf = USART1->RDR;
}

int main(void){

	USART1->CR1 = 0x10000000;	// Set bit 28 and clear bit 12 for 7 bit data
	read_DR();   

	return 0;
}
