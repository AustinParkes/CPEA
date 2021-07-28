#include <unicorn/unicorn.h>
#include <stdint.h>
#include "toml.h"

void error();					// Prints Error Messages in parsing
void emuConfig();				// Configure Emulator.
toml_table_t* parseTOML();		// Gather data from TOML file.
void map_memory();				// Create memory map for the emulator.
void flash_init();				// Initialize flash memory with code and data
void reg_init();				// Initialize all ARM registers.
int mmioConfig();				// Configure peripheral emulation.
int setFlags();					// Sets the configured status register values.
void parseKeys();				// Gathers key data and stores it.

#define MAX_MMIO 16				// TODO: Find an appropriate max number (16?)
#define MAX_SR 20               // TODO: Find an appropriate max number
#define MAX_INST 1000           // TODO: Find better max number for saved SR instances?

// Set kth bit in a register
#define SET_BIT(reg, k)     (reg |= (1<<k))	
#define CLEAR_BIT(reg, k)   (reg &= ~(1<<k))

/* Memory Map for Cortex-M */
uint32_t CODE_ADDR;             // Addr of Code section
uint32_t CODE_SIZE;             // Size of Code section
uint32_t SRAM_ADDR;             // Addr of SRAM section
uint32_t SRAM_SIZE;             // Size of SRAM section
uint32_t MMIO_ADDR;             // Addr of MMIO section
uint32_t MMIO_SIZE;             // Size of MMIO section
uint32_t EXT_RAM_ADDR;          // Addr of Ext RAM section
uint32_t EXT_RAM_SIZE;          // Size of Ext RAM section
uint32_t EXT_DEV_ADDR;          // Addr of Ext Device section
uint32_t EXT_DEV_SIZE;          // Size of Ext Device section
uint32_t PRIV_BUS_ADDR;         // Addr of Private Peripheral Bus section
uint32_t PRIV_BUS_SIZE;         // Size of Private Peripheral Bus section
uint32_t VENDOR_MEM_ADDR;       // Addr of Vendor-specific memory section
uint32_t VENDOR_MEM_SIZE;       // Size of Vendor-specific memory section

/* Firmware */
uint32_t CODE_ADDR;	        // Start address of code
uint32_t DATA_ADDR;			// Start address of data
uint32_t START;             // Start addr of FW execution
uint32_t END;               // End addr of FW execution

/* ARM Core Registers */	
uint32_t r_r0;          // r0
uint32_t r_r1;          // r1
uint32_t r_r2;          // r2 
uint32_t r_r3;          // r3
uint32_t r_r4;          // r4
uint32_t r_r5;          // r5
uint32_t r_r6;          // r6
uint32_t r_r7;          // r7 
uint32_t r_r8;          // r8
uint32_t r_r9;          // r9
uint32_t r_r10;         // r10
uint32_t FP;            // r11  
uint32_t r_r12;         // r12
uint32_t SP;            // r13
uint32_t LR;            // r14
uint32_t PC;            // r15

uint32_t CPSR;          // Current Program Status Register
uint32_t CONTROL;       // CONTROL Register
/* Interrupts */
uc_hook exit_handle;    // Handle for exiting interrupt handlers
int INTR_EN;            // Interrupt firing enabled/disabled for emulator
int VToffset;           // Vector Table offset (Default to 0)
int exc_return;         // Keeps the exc_return value

// Remembers processor mode to return from handlers
typedef enum proc_mode{
    ARM = 0,
    Thumb
} proc_mode;
proc_mode mode;

/*******************/
/*** MMIO Config ***/
/*******************/
int mod_count;              // Total number of peripheral modules	
int SR_count;               // Number of SR for a module
int DR_count;               // Number of DR for amodule

// These keep track of the callback range for MMIO accesses
uint32_t minMMIOaddr;
uint32_t maxMMIOaddr;

// min/max register addresses for any given peripheral module. (Helps locate modules in findMod())
uint32_t minPeriphaddr;
uint32_t maxPeriphaddr;

// Callback Declarations 
int pre_read_MMIO();    // Before an MMIO register is read
int post_read_MMIO();   // After an MMIO register is read
void write_MMIO();      // After an MMIO register is written to
void enter_SVC();       // Callback to enter SVC handler  
void exit_intr();       // Callback for leaving interrupt handlers  


// Peripherals and their corresponding ID to determine which structures belong to which periph.
enum periphID {uartID, gpioID, genericID};

// To index correct SR or DR
enum Status_Register {SR1, SR2, SR3, SR4, SR5, SR6, SR7, SR8};
enum Data_Register {DR1, DR2};

// TODO: Need to init these arrays because they contain garbage.
// MMIO Structure for all peripherals. 
typedef struct MMIO{
    // MMIO Metadata
    int periphID;                           // ID of which peripheral this struct is for. e.g. uart, gpio, etc.
    int modID;                              // ID for which module this is. e.g. 0, 1, 2, etc
    int modCount;                           // Number of total modules for this peripheral
    // FIXME: Currently not finding min/max for modules. 
    int minAddr;                            // Lowest register address for this module 
    int maxAddr;                            // Highest register address for this module

    uint32_t BASE_ADDR;
	
    uint32_t SR_ADDR[MAX_SR];                   // TODO: Find a reasonable number for possible # of SR addresses
    uint32_t DR_ADDR[2];					
		
    // Reset values to init memory with		
    uint32_t SR_RESET[MAX_SR];                  // TODO: Same as above
    uint32_t DR_RESET[2];

    // UART regs to temporarily hold values	
    uint32_t SR[MAX_SR];                        // TODO: Same as above above
    uint32_t DR[2];
	
	// Instance flag to see if instance exists for this module. 
	int SR_INST;

	
} MMIO_handle;

// Create an MMIO instance.
MMIO_handle *MMIO[MAX_MMIO];        // Holds pointers to different instances of peripherals		


int inst_i;                         // Instance index, to keep track of current index when allocating.  
// Saves SR instances for particular SR accesses.
typedef struct SR_INSTANCE{

    uint32_t PROG_ADDR;                   // Program address SR is accessed at.
    int BIT;                              // SR Bit location 
    int VAL;                              // SR Bit value
    
} INST_handle;

// Create SR_INSTANCE instance. 
INST_handle *SR_INSTANCE[MAX_INST];






