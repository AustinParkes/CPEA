#include <stdint.h>
#include "cpea/toml.h"

void error(const char *, const char *, const char *);					// Prints Error Messages in parsing
toml_table_t *parseTOML(toml_table_t *);		// Gather data from TOML file.
void emuConfig(void);
int mmioConfig(toml_table_t *);				// Configure peripheral emulation.
int setFlags(toml_table_t *, int);					// Sets the configured status register values.
void parseKeys(char *, const char *, toml_table_t *, const char *, int);				// Gathers key data and stores it.
void cp_mem_write(uint64_t, const void *, size_t);
void cp_mem_read(uint64_t, void *, size_t);

/*
void intr_setup();              // Automatic stacking and other setups for interrupt handlers
// Callback Declarations 
int pre_read_MMIO();    // Before an MMIO register is read
int post_read_MMIO();   // After an MMIO register is read
void write_MMIO();      // After an MMIO register is written to
void enter_intr();      // Callback to enter exception handlers  
void exit_intr();       // Callback for leaving exception handlers
void write_SCS();       // Monitor writes to System Control Space
void fire_intr();       // Fires interrupt every 1,000 basic blocks (bbls)
*/

// Max array sizes
#define MAX_MMIO 16				// TODO: Find an appropriate max number (16?)
#define MAX_SR 20               // TODO: Find an appropriate max number
#define MAX_INST 1000           // TODO: Find better max number for saved SR instances?

// Set kth bit in a register
#define SET_BIT(reg, k)     (reg |= (1<<k))	
#define CLEAR_BIT(reg, k)   (reg &= ~(1<<k))

// Check kth bit in a register
#define CHECK_BIT(reg, k)   (reg & (1<<k))

/* Firmware */
/*
extern uint32_t CODE_ADDR;
extern uint32_t DATA_ADDR;
extern uint32_t START;             // Start addr of FW execution
extern uint32_t END;               // End addr of FW execution
*/

/* ARM Core Registers */
/*	
extern uint32_t r_r0;          // r0
extern uint32_t r_r1;          // r1
extern uint32_t r_r2;          // r2 
extern uint32_t r_r3;          // r3
extern uint32_t r_r4;          // r4
extern uint32_t r_r5;          // r5
extern uint32_t r_r6;          // r6
extern uint32_t r_r7;          // r7 
extern uint32_t r_r8;          // r8
extern uint32_t r_r9;          // r9
extern uint32_t r_r10;         // r10
extern uint32_t FP;            // r11  
extern uint32_t r_r12;         // r12
extern uint32_t SP;            // r13
extern uint32_t LR;            // r14
extern uint32_t PC;            // r15
*/


/* Interrupts */
/*
extern int INTR_EN;            // Interrupt firing enabled/disabled for emulator
extern int INTR_PTR;           // Points to next interrupt to fire
extern int n_cnt;              // Points to ISERn to fire interrupts
extern int m_cnt;              // Points to a bit in ISERn to fire interrupts
*/


/*******************/
/*** MMIO Config ***/
/*******************/
extern int mod_count;              // Total number of peripheral modules	
extern int SR_count;               // Number of SR for a module
extern int DR_count;               // Number of DR for a module

// min/max register addresses for any given peripheral module. (Helps locate modules in findMod())
extern uint32_t minPeriphaddr;
extern uint32_t maxPeriphaddr;


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

// Create a global MMIO instance.
extern MMIO_handle *MMIO[MAX_MMIO];      // Holds pointers to different instances of peripherals		


// Saves SR instances for particular SR accesses.
extern int inst_i;                         // Instance index, to keep track of current index when allocating.  
typedef struct SR_INSTANCE{

    uint32_t PROG_ADDR;                   // Program address SR is accessed at.
    int BIT;                              // SR Bit location 
    int VAL;                              // SR Bit value
    
} INST_handle;

// Create global SR_INSTANCE instance. 
extern INST_handle *SR_INSTANCE[MAX_INST];


