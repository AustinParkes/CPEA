/*
 * MachineState for CPEA. Contains all configurable variables needed for Cortex-M
 * TODO: Extend description
 * Written by Austin Parkes.
*/

#ifndef HW_ARM_CPEA_H_
#define HW_ARM_CPEA_H_

#include <stdint.h>
#include "cpea/toml.h"
#include "hw/boards.h"
#include "hw/sysbus.h"
#include "hw/arm/armv7m.h"
#include "hw/irq.h"
#include "sysemu/sysemu.h"
#include "chardev/char-fe.h"
#include "chardev/char.h"

#define SET_BIT(reg, k)     (reg |= (1<<k))	
#define CLEAR_BIT(reg, k)   (reg &= ~(1<<k))
#define CHECK_BIT(reg, k)   (reg & (1<<k))

#define MAX_MMIO 100			// TODO: Find an appropriate max number
#define MAX_MODS 16             // TODO: Find an appropriate max number
#define MAX_CR 20               // TODO: Find an appropriate max number
#define MAX_SR 20               // TODO: Find an appropriate max number
#define MAX_DR 2
#define MAX_INTR 10             // TODO: Find an appropriate max number
#define MAX_INST 1000           // TODO: Find better max number for saved SR instances?

#define TYPE_CPEA_MACHINE MACHINE_TYPE_NAME("cpea")
OBJECT_DECLARE_SIMPLE_TYPE(CpeaMachineState, CPEA_MACHINE)

#define TYPE_CPEA_MMIO "cpea-mmio"
OBJECT_DECLARE_SIMPLE_TYPE(CpeaMMIOState, CPEA_MMIO)

#define TYPE_CPEA_IRQ_DRIVER "cpea-irq-driver"
OBJECT_DECLARE_SIMPLE_TYPE(CpeaIRQDriverState, CPEA_IRQ_DRIVER)

struct CpeaMachineState {
    MachineState parent;
    
    /* Core */
    char cpu_model[30];
    
    unsigned int has_bitband :1;    /* True/False */
    unsigned int num_irq;           /* # External Interrupts */
    
    /* Memory */
    uint32_t flash_base;
    uint32_t flash_size;

    uint32_t sram_base;
    uint32_t sram_size;
    
    uint32_t sram_base2;
    uint32_t sram_size2;
    
    uint32_t sram_base3;
    uint32_t sram_size3;
    
    ARMv7MState *armv7m;
    CpeaIRQDriverState *irq_state;

};

// Don't think we need this anymore. XXX: If we must, could turn this into a "peripheral model" Device
struct CpeaMMIOState {
    SysBusDevice parent_obj;
    MemoryRegion *mmio; 

    qemu_irq *irq;      
};


struct CpeaIRQDriverState {
    SysBusDevice parent_obj;
       
    qemu_irq *irq;    
    int *IRQn_list;  
};

extern int IRQtotal;
extern int mmio_total;            
extern int CR_count;
extern int SR_count;
extern int DR_count;
extern uint32_t minPeriphaddr;
extern uint32_t maxPeriphaddr;
extern int inst_i;

enum regType {CR_type, SR_type, DR_type};
enum periphID {null, uartID, gpioID, genericID};
enum Status_Register {SR1, SR2, SR3, SR4, SR5, SR6, SR7, SR8};
enum Data_Register {DR1, DR2};


enum dType {STRING = 1, INTEGER = 2};
enum dRep {REG = 1, BIT = 2};

// Interrupt types 
enum uart_intr {RXFF};


/* XXX: Any MMIO struct that has interrupts enabled should have
        its own interrupt structure
        
      - It should be possible for a peripheral to have multiple 
        interrupts enabled at the same time.
        Could make an array out of each of the variables in the struct,
        and have the interrupt type be an index in the array for fast indexing.
        e.g. interrupt.type[RXFF] and interrupt.type[TXComplete]
*/
typedef struct interrupt {
        
    // Flag table to say which interrupts are emulated by user
    int enabled;
    
    // Flag table that indicates partial emulation
    int partial;
    
    // CR that enables the interrupt type
    uint32_t CR_enable[5];
    uint32_t CR_i[5];
    
    // SR that is set upon a condition to generate the interrupt type
    uint32_t SR_generate[5];
    uint32_t SR_i[5];
    
    // UART specific    
    uint32_t RXWATER_val[5];
    uint32_t RXWATER_addr[5];      

} interrupt;
		
// MMIO Structure for all peripherals. 
typedef struct MMIO{

    // Metadata
    int periphID;                           // ID of which peripheral this struct is for. e.g. uart, gpio, etc.
    int modID;                              // ID for which module this is. e.g. 0, 1, 2, etc
    int modCount;                           // Number of total modules for this peripheral
    int minAddr;                            // Lowest register address for this module 
    int maxAddr;                            // Highest register address for this module
    int mmioSize;                           // Number of addresses this peripheral takes up 

    // Registers
    uint32_t BASE_ADDR;
	
	uint32_t CR_ADDR[MAX_CR];
    uint32_t SR_ADDR[MAX_SR];                  
    uint32_t DR_ADDR[MAX_DR];					
	
	// XXX: What is the point of these? Reset values should go into actual registers ...
	uint32_t CR_RESET[MAX_CR];		
    uint32_t SR_RESET[MAX_SR];                  
    uint32_t DR_RESET[MAX_DR];

    uint32_t CR[MAX_CR];
    uint32_t SR[MAX_SR];                        
    uint32_t DR[MAX_DR];
	
	// SR instance flag
	int SR_INST;
	
	// Interrupts
	int irq_enabled;
	int irqn;
	qemu_irq irq;
	interrupt *interrupt;	
	
	// Peripheral Interaction
	CharBackend chrbe;
	
	// Peripheral Models XXX: Stuff like FIFOs should go here.
	uint8_t rx_fifo[16];    // TODO: Using default size of 16 for now. Would likely make this configurable.
	int tail;               // 
	int queue_count;        // Number of datawords in rx_fifo

	
} CpeaMMIO;
extern CpeaMMIO *MMIO[MAX_MMIO];

// Saves SR instances for particular SR accesses.
typedef struct SR_INSTANCE{

    uint32_t INST_ADDR;                   // Program address SR is accessed at.
    int BIT;                              // SR Bit location   
    int VAL;                              // SR Bit 0/1             //unsigned int VAL :1; TODO: Could make this binary.
    
} INST_handle;
extern INST_handle *SR_INSTANCE[MAX_INST];


/**
 * genericIntrConfig: Interrupt Configuration for generic peripherals
 *
 */
void genericIntrConfig(toml_table_t* mmio, char* p_name, const char* module_str, 
                toml_table_t* table_ptr, const char* table_str, int struct_i);

/**
 * uartIntrConfig: UART Interrupt Configuration
 *
 */
void uartIntrConfig(toml_table_t* mmio, char* p_name, const char* module_str, 
                toml_table_t* table_ptr, const char* table_str, int struct_i);

/**
 * RXFFParse: Parse RX FIFO Full / RX Data Register Full interrupts
 *
 * Returns 0-Error, 1-Success
 */
int RXFFParse(toml_table_t* TablePtr, toml_table_t* AddrTab, 
              int intrType, int struct_i);


/**
 * CheckData: Checks the data type entered by user (string / integer)
 *
 * Returns 0-Error, 1-String, 2-Integer
 *
 */
int CheckIntrData(toml_table_t* InlineTable, const char *InlineTableName, 
                  const char *InlineTableKey, int dataRep);

/**
 * GetData: Retrieves data from an inline table 
 *
 * Returns a union containing a register string or integer value
 *
 */
toml_datum_t GetIntrData(toml_table_t* InlineTable, const char *InlineTableName,  
                const char *InlineTableKey, int dataType, int dataRep);

/**
 * checkExistance: Check if a register exists and is configured by the user
 * 
 * Returns 0-Invalid Format 1-Valid Register 2-No Register
 * Prints error message when a register doesn't exist or is invalid
 *
 */
int checkExistance(toml_datum_t IntrData, toml_table_t* AddrTab, 
                const char *InlineTableName, const char *InlineTableKey);

/**
 * checkPartial: Checks if a control register is entered for emulation                
 *               Partial emulation if no CR is entered
 *               Full emulation if a CR is entered
 *                  
 * Returns 0-Full Emulation 1-Partial Emulation
 *
 */
int checkPartial(const char *InlineTableName, const char *InlineTableKey,
                 int struct_i);

/**
 * checkIRQ: Check if IRQ is enabled during interrupt parsing 
 *           Interrupt parsing will fail if no IRQ is enabled
 *
 *  Returns 0-No IRQ 1-IRQ configured
 */
int checkIRQ(const char *InlineTableName, int struct_i);

/**
 * regExists: Checks if user entered a register that exists in the 'addr' table 
 *            Makes sure user entered a valid register
 *
 * Returns 0-Invalid 1-Valid 2-Nothing entered
 */
int regExists(toml_datum_t IntrData, toml_table_t* AddrTab, 
              const char *InlineTableName, const char *InlineTableKey);

/**
 * getRegAddr: Gets the address of a register. We need addresses
 *             of some registers to emulate them when they are accessed.
 *
 * Returns an address
 *
 */
int getRegAddr(toml_datum_t IntrData, toml_table_t* AddrTab);


/**
 * getRegReset: Gets the reset value of a register. We need the reset
 *              value to give a register its inital value to emulate it.
 *
 * Returns a reset value
 *
 */
int getRegReset(toml_datum_t IntrData, toml_table_t* AddrTab);

/**
 * parseConfig: 
 *
 */          
toml_table_t *parseConfig(toml_table_t *, CpeaMachineState **);	

/**
 * emuConfig: 
 *
 */
CpeaMachineState *emuConfig(CpeaMachineState *);

/**
 * mmioConfig: 
 *
 */
int mmioConfig(toml_table_t *);	
	
/**
 * setFlags: 
 *
 */		            
int setFlags(toml_table_t *, int);
	
/**
 * parseKeys:
 *
 */				   
void parseKeys(toml_table_t*, char *, const char *, toml_table_t *, const char *, int);

/**
 * findMod: Find peripheral module accessed in callback.
 *
 */	
CpeaMMIO *findMod(uint64_t, CpeaMMIO**);

/**
 * error: 
 *
 */
void error(const char *, const char *, const char *, const char *); 

#endif /* CPEA_H_ */
