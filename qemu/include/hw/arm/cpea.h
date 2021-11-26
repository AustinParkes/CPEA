/*
 * MachineState for CPEA. Contains all configurable variables needed for Cortex-M
 * TODO: Extend description
 * Written by Austin Parkes.
*/

#ifndef CPEA_H_
#define CPEA_H_

#include "hw/boards.h"
#include "hw/sysbus.h"

#define MAX_MMIO 100			// TODO: Find an appropriate max number
#define MAX_SR 20               // TODO: Find an appropriate max number

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

};

// MMIO callback address and its paired with 'MMIO' data
typedef struct MMIOkey {
    int AddrKey;
    int MMIOIndex;
    int regType;        // CR, SR, DR
    int RegIndex;
} MMIOkey;
extern MMIOkey MMIOHashTable[10000];

// MMIO Structure for all peripherals. 
typedef struct MMIO{
    // Metadata
    
    int periphID;                           // ID of which peripheral this struct is for. e.g. uart, gpio, etc.
    int modID;                              // ID for which module this is. e.g. 0, 1, 2, etc
    int modCount;                           // Number of total modules for this peripheral
    
    // FIXME: Currently not finding min/max for modules. 
    int minAddr;                            // Lowest register address for this module 
    int maxAddr;                            // Highest register address for this module

    uint32_t BASE_ADDR;
	
	// TODO: Find reasonable number of SR/DR maxes
    uint32_t SR_ADDR[MAX_SR];                  
    uint32_t DR_ADDR[2];					
			
    uint32_t SR_RESET[MAX_SR];                  
    uint32_t DR_RESET[2];

    uint32_t SR[MAX_SR];                        
    uint32_t DR[2];
	
	int SR_INST;
	
	int irq_enabled;
	int irqn;
	
} CpeaMMIO;
extern CpeaMMIO *MMIO[MAX_MMIO];

struct CpeaMMIOState {
    SysBusDevice parent_obj;

    CpeaMMIO *CpeaPeriph;   

    qemu_irq irq;      
};

struct CpeaIRQDriverState {
    SysBusDevice parent_obj;
    
    qemu_irq irq;
};

#endif /* CPEA_H_ */
