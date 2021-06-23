#include <unicorn/unicorn.h>
#include <stdint.h>
#include "toml.h"

void error();					// Prints Error Messages in parsing
void emuConfig();				// Configure Emulator.
toml_table_t* parseTOML();		// Gather data from TOML file.
void map_memory();				// Create memory map for the emulator.
void reg_init();				// Initialize all ARM registers.
int mmioConfig();				// Configure peripheral emulation.
int setFlags();					// Sets the configured status register values.
void parseKeys();				// Gathers key data and stores it.

#define MAX_MMIO 16				// TODO: Find a better max number (16?)

// Set kth bit in a register
#define SET_BIT(reg, k)		(reg |= (1<<k))	

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

/*******************/
/*** MMIO Config ***/
/*******************/
int mod_count;				// Number of peripheral modules			TODO: Generate from python program/configuration

// These keep track of the callback range for UART register accesses. 
uint32_t minPeriphaddr;
uint32_t maxPeriphaddr;

// MMIO Callback Declarations 
void pre_read_MMIO();	// Before an MMIO register is read
void post_read_MMIO();	// After an MMIO register is read
void write_MMIO();		// After an MMIO register is written to

// Peripherals and their corresponding ID to determine which structures belong to which periph
//const char periph_str[2][10];
enum periphID {uart, gpio};

// To index correct SR or DR
enum Status_Register {SR1, SR2, SR3, SR4, SR5, SR6, SR7, SR8};
enum Data_Register {DR1, DR2};

// TODO: Need to init these arrays because they contain garbage.
// UART 32 bit peripheral registers
typedef struct MMIO{
	
	int periphID;							// ID of which peripheral this struct is for. e.g. uart, gpio, etc.
	int modID;								// ID for which module this is. e.g. 0, 1, 2, etc
	int minAddr;							// Lowest register address for this periph
	int maxAddr;							// Highest register address for this periph

	uint32_t BASE_ADDR;
	
	uint32_t SR_ADDR[20];					// TODO: Find a reasonable number for possible # of SR addresses
	uint32_t DR_ADDR[2];					
		
	// Reset values to init memory with		
	uint32_t SR_RESET[20];					// TODO: Same as above
	uint32_t DR_RESET[2];

	// UART regs to temporarily hold values	
	uint32_t SR[20];						// TODO: Same as above above
	uint32_t DR[2];
	
} MMIO_handle;

// Create an MMIO instance. Will make more generic handles if needed.
MMIO_handle *MMIO[MAX_MMIO];		// Holds pointers to different instances of UART modules.		


