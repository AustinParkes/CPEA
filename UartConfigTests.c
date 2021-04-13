#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/*** Configuration Register Checks ***/
// Check if kth bit is set or not in register (Check if USART enabled(1) / disabled(0)) 
#define CHECK_ENABLE(reg, k)	(reg & (1<<k)) 

// Check if any 2 bits are both 0. (Check if UART 8-N-1)
#define CHECK_WORDLENGTH8(reg,k1,k2)  (~reg & (1<<k1)) && (~reg & (1<<k2))

// Check among 2 bits if 1 is set and the other is not set. (check if UART 7-N-1)
#define CHECK_WORDLENGTH7(reg, k1Set, k2Not)  (reg & (1<<k1Set)) && (~reg & (1<<k2Not))

// Check if any 2 bits are both 0 (Check if 1 stop bit)
#define CHECK_STOPBITS1(reg,k1,k2)  (~reg & (1<<k1)) && (~reg & (1<<k2))

// Check if kth bit is set or not in register (Check if oversample8 (Oversample8 (1)) / oversample16 (disabled(0)) )
#define CHECK_OVERSAMPLE(reg, k)	(reg & (1<<k)) 

// Check if kth bit is set or not in register (Check if transmitter enabled (1) / disabled (0))
#define CHECK_TX_ENABLE(reg, k)		(reg & (1<<k)) 

// Check if kth bit is set or not in register (Check if receiver enabled (1) / disabled (0))
#define CHECK_RX_ENABLE(reg, k)		(reg & (1<<k))



/*** Status Register Sets/Clears ***/ 
// Check any bit for SR testing
#define CHECK_BIT(reg, k)	(reg & (1<<k))

// Set kth bit in register (Sets the Transmit enable Acknowledge flag if transmitter is enabled)
#define SET_TEACK(reg, k)	(reg |= (1<<k))

// Clear kth bit in register (Clears the Transmit enable Acknowledge flag if transmitter is disabled)
#define CLEAR_TEACK(reg, k)		(reg &= ~(1<<k))			

// Set kth bit in register (Sets the Receive enable Acknowledge flag if receiver is enabled)
#define SET_REACK(reg, k)	(reg |= (1<<k))

// Clear kth bit in register (Clears the Receive enable Acknowledge flag if receiver is disabled)
#define CLEAR_REACK(reg, k)		(reg &= ~(1<<k))

int main()
{

	uint32_t reg = 0xFFFFFFFF;   // Set to all 1s and modify from here
	uint32_t s_reg;
	
	printf("***** Configuration Checks *****\n\n");
    /*** CHECK_ENABLE ***/
    reg = 0xFFFFFFFE;
	printf("CHECK_ENABLE\n");
	if (CHECK_ENABLE(reg, 0))
		printf("    Enabled (Incorrect)\n\n");
	else if (!CHECK_ENABLE(reg, 0))
		printf("	Disabled (Correct)\n\n");
		
	/*** CHECK_WORDLENGTH ***/
	reg |= 0x10000000;   	// set bit 28
	reg &= 0xFFFFEFFF;     	// Clear bit 12
	printf("CHECK_WORDLENGTH\n");
	if (CHECK_WORDLENGTH8(reg,28,12))
		printf("	8Bit (Incorrect)\n\n");
	else if (CHECK_WORDLENGTH7(reg, 28, 12))
		printf(" 	7Bit (Correct)\n\n");
	
	/*** CHECK_STOPBITS ***/
	reg &= 0xFFFFCFFF;     	// Clear bits 13:12
	printf("CHECK_STOPBITS\n");
	if (CHECK_STOPBITS1(reg,13,12))
		printf("	1Stop (Correct)\n\n");
		
	/*** CHECK_OVERSAMPLE ***/
	reg &= 0xFFFF7FFF;     	// Clear bit 15	
	printf("CHECK_OVERSAMPLE\n");
	if (CHECK_OVERSAMPLE(reg, 15)){
		printf("	Oversample8 (Incorrect)\n\n");
	}
	else if (!CHECK_OVERSAMPLE(reg, 15)){
		printf("	Oversample16 (Correct)\n\n");
	}
	
	/*** CHECK_TX_ENABLE ***/
	reg |= 0x0000000C;		// Enable bits 3:2
	printf("CHECK_TX_ENABLE\n");
	if (CHECK_TX_ENABLE(reg, 3))
		printf("	Tx Enabled (Correct)\n\n");
	else if(!CHECK_TX_ENABLE(reg, 3))
		printf("	Tx Disabled (Incorrect)\n\n");
		
	/*** CHECK_RX_ENABLE ***/
	printf("CHECK_RX_ENABLE\n");
	if (CHECK_RX_ENABLE(reg, 2))
		printf("	Rx Enabled (Correct)\n\n");
	else if(!CHECK_RX_ENABLE(reg, 2))
		printf("	Rx Disabled (Incorrect)\n\n");
		
	/*
		Status Register Set/Clear testing
	*/
	printf("***** Status Register Sets/Clears *****\n\n");
	/*** SET_TEACK ***/
	printf("SET_TEACK\n");
	s_reg = 0x0;
	SET_TEACK(s_reg, 21);
	if (CHECK_BIT(s_reg, 21))
		printf("	TEACK Set (Correct): %x\n\n", s_reg);
	else
		printf("	TEACK not set (Incorrect): %x\n\n", s_reg);	
		
	/*** CLEAR_TEACK ***/
	printf("CLEAR_TEACK\n");
	s_reg = 0xffffffff;
	CLEAR_TEACK(s_reg, 21);
	if (!CHECK_BIT(s_reg, 21))
		printf("	TEACK cleared (Correct): %x\n\n", s_reg);
	else
		printf("	TEACK not cleared (Incorrect): %x\n\n", s_reg);	

	/*** SET_REACK ***/
	printf("SET_REACK\n");
	s_reg = 0x0;
	SET_REACK(s_reg, 22);
	if (CHECK_BIT(s_reg, 22))
		printf("	REACK Set (Correct): %x\n\n", s_reg);
	else
		printf("	REACK not set (Incorrect): %x\n\n", s_reg);	
		
	/*** CLEAR_REACK ***/
	printf("CLEAR_REACK\n");
	s_reg = 0xffffffff;
	CLEAR_REACK(s_reg, 22);
	if (!CHECK_BIT(s_reg, 22))
		printf("	REACK cleared (Correct): %x\n\n", s_reg);
	else
		printf("	REACK not cleared (Incorrect): %x\n\n", s_reg);		
	



	return 0;
}
