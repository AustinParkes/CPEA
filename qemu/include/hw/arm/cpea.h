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
#define MAX_SR 20               // TODO: Find an appropriate max number
#define MAX_DR 2
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

extern int IRQtotal;
extern int mmio_total;            
extern int IOregTotal;
extern int SR_count;
extern int DR_count;
extern uint32_t minPeriphaddr;
extern uint32_t maxPeriphaddr;

enum regType {CR_type, SR_type, DR_type};
enum periphID {uartID, gpioID, genericID};
enum Status_Register {SR1, SR2, SR3, SR4, SR5, SR6, SR7, SR8};
enum Data_Register {DR1, DR2};

		
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
	
	// TODO: Find reasonable number of SR/DR maxes
    uint32_t SR_ADDR[MAX_SR];                  
    uint32_t DR_ADDR[MAX_DR];					
			
    uint32_t SR_RESET[MAX_SR];                  
    uint32_t DR_RESET[MAX_DR];

    uint32_t SR[MAX_SR];                        
    uint32_t DR[MAX_DR];
	
	// SR instance
	int SR_INST;
	
	// Interrupts
	int irq_enabled;
	int irqn;
	qemu_irq *irq;
	
	// Peripheral Interaction
	CharBackend chrbe;
	
	// Peripheral Models XXX: Stuff like FIFOs should go here.
	uint8_t rx_fifo[16];    // TODO: Using default size of 16 for now. Would likely make this configurable.
	int head;
	int queue_count;
    

} CpeaMMIO;
extern CpeaMMIO *MMIO[MAX_MMIO];

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

// Saves SR instances for particular SR accesses.
extern int inst_i;
typedef struct SR_INSTANCE{

    uint32_t INST_ADDR;                   // Program address SR is accessed at.
    int BIT;                              // SR Bit location   
    int VAL;                              // SR Bit 0/1             //unsigned int VAL :1; TODO: Could make this binary.
    
} INST_handle;
extern INST_handle *SR_INSTANCE[MAX_INST];

/**
 * error: 
 *
 */
void error(const char *, const char *, const char *, const char *); 

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
void parseKeys(char *, const char *, toml_table_t *, const char *, int);

/**
 * findMod: Find peripheral module accessed in callback.
 *
 */	
CpeaMMIO *findMod(uint64_t, CpeaMMIO**);

#endif /* CPEA_H_ */
