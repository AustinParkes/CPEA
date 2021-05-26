#include <unicorn/unicorn.h>
#include <stdint.h>
#include "toml.h"

void error();					// Prints Error Messages in parsing
void emuConfig();				// Configure Emulator.
toml_table_t* parseTOML();		// Gather data from TOML file.
void map_memory();				// Create memory map for the emulator.
void reg_init();				// Initialize all ARM registers.
int uartConfig();				// Configure UART emulation.
void uartInit();				// Initiliazes UART mmio registers.

#define MAX_UART 99

/* Memory Map */
uint32_t FLASH_ADDR;
uint32_t FLASH_SIZE;
uint32_t SRAM_ADDR;
uint32_t SRAM_SIZE;
uint32_t MMIO_ADDR;
uint32_t MMIO_SIZE;

/* Firmware */
uint32_t CODE_ADDR;
//uint32_t CODE_SIZE;   Determined by file at the moment
uint32_t DATA_ADDR;
//uint32_t DATA_SIZE;   Determine by file at the moment
uint32_t START;
uint32_t END;

/* ARM Core Registers */	
uint32_t r_r0;     		// r0
uint32_t r_r1;     		// r1
uint32_t r_r2;     		// r2 
uint32_t r_r3;     		// r3
uint32_t r_r4;     		// r4
uint32_t r_r5;     		// r5
uint32_t r_r6;     		// r6
uint32_t r_r7;     		// r7 
uint32_t r_r8;     		// r8
uint32_t r_r9;     		// r9
uint32_t r_r10;    		// r10
uint32_t FP;      		// r11  
uint32_t r_r12;    		// r12
uint32_t SP;      		// r13
uint32_t LR;			// r14


/*****************/
/*** UART Config ***/
/*****************/
bool UART_enable;   		// Disabled by default (CR1)
int uart_count;				// Number of uart modules		TODO: Generate from python program
int reg_count;				// Number of UART registers		TODO: Generate from python program

// These keep track of the callback range for UART register accesses. 
uint32_t minUARTaddr;
uint32_t maxUARTaddr;

uc_hook handle1;			// Used by uc_hook_add to give to uc_hook_del() API
uc_hook handle2;
uc_hook handle3;

// UART Callback Declarations 
void pre_read_UART();	// Before an UART register is read
void post_read_UART();	// After an UART register is read
void write_UART();		// After an UART register is written to


// Enumerate Different UART Configurations based on UART configuration registers
/* 
2) TODO: In future, user may be able to map these configuration checks to particular registers
   instead of hardcoding them for a particular configuration register.
   
   NOTE: (Can likely merge this with step 3)
   
   In fact, could have a function that specifically checks the configuration mappings
   and disables certain cases underneath registers that those cases should not be there for
   and enables those congifuration cases for the registers they are mapped to.
   
   In this idea, we would have a copy of the enumerations below for each configuration register
   and just write 0 to the enumerations that are disabled.
   
   If statements might be better for this because 'if(0)' for disabled enumerations would not execute
   but case(0) would execute still.
   
   Once this is configured by user, can move to 3) and user can specifically
   say which bits need to be checked for certain functionality.         
*/
enum UART_Config{
	ENABLE, 		// Check UART enabled/disabled
	WORDLENGTH,     // Check the word length of UART Data   (Only possible when UART Disabled)
	STOP_BITS,      // Check number of stop bits 			(Only possible when UART Disabled) (Ignored   :'(   )
	PARITY_ENABLE, 	// Check if Parity Enabled	   			(Only possible when UART Disabled) (Ignored   :'(   )    
	OVERSAMPLE,     // Check oversampling mode				(Only possible when UART Disabled)
	BAUDRATE,		// Check baudRate														   (Ignored   :'(   ) 
	TxENABLE,       // Check transmission enable
	RxENABLE,       // Check reception enable
	TCCF			// Check Transmission Complete Clear Flag
};


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
	uint32_t CR1_ADDR;		// CR1
	uint32_t CR2_ADDR;		// CR2
	uint32_t CR3_ADDR;		// CR3
	uint32_t CR4_ADDR;
	uint32_t CR5_ADDR;		// BRR
	uint32_t CR6_ADDR;		// GTPR
	uint32_t CR7_ADDR;		// RTOR
	uint32_t CR8_ADDR;		// RQR
	uint32_t CR9_ADDR;		// ICR	flipped with ISR
	uint32_t SR1_ADDR;		// ISR	flipped with ICR
	uint32_t SR2_ADDR;		
	uint32_t DR1_ADDR;		// RDR
	uint32_t DR2_ADDR;		// TDR
	
	/* 
	In future, May need to make these names for generic for later configuration.
	May also need to add an 8 bit mode for 8 bit wide peripheral registers.
	Would maybe need to create a new "UART8" struct entirely for that. Could call this one "UART32"
	*/ 	
	
	// Reset values to init memory with
	uint32_t CR1_RESET;		// CR1
	uint32_t CR2_RESET;		// CR2
	uint32_t CR3_RESET;		// CR3
	uint32_t CR4_RESET;
	uint32_t CR5_RESET;		// BRR
	uint32_t CR6_RESET;		// GTPR
	uint32_t CR7_RESET;		// RTOR
	uint32_t CR8_RESET;		// RQR
	uint32_t CR9_RESET;		// ICR
	uint32_t SR1_RESET;		// ISR
	uint32_t SR2_RESET;
	uint32_t DR1_RESET;		// RDR
	uint32_t DR2_RESET;		// TDR
	
/* 
	In future, May need to make these names for generic for later configuration.
	May also need to add an 8 bit mode for 8 bit wide peripheral registers.
	Would maybe need to create a new "UART8" struct entirely for that. Could call this one "UART32"
*/ 	
	// UART regs to temporarily hold values
	uint32_t CR1;		// CR1
	uint32_t CR2;		// CR2
	uint32_t CR3;		// CR3
	uint32_t CR4;
	uint32_t CR5;		// BRR
	uint32_t CR6;		// GTPR
	uint32_t CR7;		// RTOR
	uint32_t CR8;		// RQR
	uint32_t CR9;		// ICR
	uint32_t SR1;		// ISR
	uint32_t SR2;
	uint32_t DR1;		// RDR
	uint32_t DR2;		// TDR
	
} UART_handle;

// Create an UART instance. Will make more generic handles if needed.
UART_handle *UART[MAX_UART];		// Holds pointers to different instances of UART modules.		


