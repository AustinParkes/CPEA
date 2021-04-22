#include <stdint.h>

void emuConfig();

/* Memory Map */
uint32_t FLASH_ADDR;
uint32_t FLASH_SIZE;
uint32_t SRAM_ADDR;
uint32_t SRAM_SIZE;
uint32_t MMIO_START;
uint32_t MMIO_SIZE;

/* Firmware */
uint32_t CODE_ADDR;
//uint32_t CODE_SIZE;   Determined by file at the moment
uint32_t DATA_ADDR;
//uint32_t DATA_SIZE;   Determine by file at the moment
uint32_t START;
uint32_t END;
uint32_t SP_INIT;
uint32_t FP_INIT;

/*****************/
/*** UART MMIO ***/
/*****************/

// UART 32 bit peripheral registers
typedef struct UART{
/*
1)	In future, these registers should be more generic (CRx, SRx, DRx)
	and the user will specifically map them individually to an address
	from their reference manual. The addresses will almost certainly not
	be in order due to the variance in register layouts among MCU reference
	manuals.
	
	Once this is configured by user, can move onto 2) and the user can 
	specifically map certain functionalities to certain registers.
*/
	uint32_t BASE_ADDR;
	uint32_t CR1_ADDR;
	uint32_t CR2_ADDR;
	uint32_t CR3_ADDR;
	uint32_t BRR_ADDR;
	uint32_t GTPR_ADDR;
	uint32_t RTOR_ADDR;
	uint32_t RQR_ADDR;
	uint32_t ISR_ADDR;
	uint32_t ICR_ADDR;
	uint32_t RDR_ADDR;
	uint32_t TDR_ADDR;
	
/* 
	In future, May need to make these names for generic for later configuration.
	May also need to add an 8 bit mode for 8 bit wide peripheral registers.
*/ 		
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

// Create an UART instance. Will make more generic handles if needed.
// Will also maybe want to automate this? depending on how many UART modules the emulator needs.  
USART_handle USART1;






