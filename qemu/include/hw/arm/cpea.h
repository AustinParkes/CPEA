/*
    Created by Austin Parkes.
*/

#ifndef CPEA_H_
#define CPEA_H_

#include "cpea/cortexm-mcu.h"
#include "hw/boards.h"


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

#define TYPE_CPEA_MACHINE MACHINE_TYPE_NAME("cpea")
OBJECT_DECLARE_SIMPLE_TYPE(CpeaMachineState, CPEA_MACHINE)

// TODO: Could move emulatorConfig.h here?

/* 
    Attempt to contain ALL the board configurations the user might need to provide
    except for MMIO.
*/
typedef struct CP_board_configs {

    CortexMCoreCapabilities CP_core;
    CortexMCapabilities CP_mem;   

} CP_config;

#endif /* CPEA_H_ */
