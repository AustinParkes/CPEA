/*
 * MachineState for CPEA. Contains all configurable variables needed for Cortex-M
 * TODO: Extend description
 * Written by Austin Parkes.
*/

#ifndef CPEA_H_
#define CPEA_H_

#include "hw/boards.h"
#include "hw/sysbus.h"

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



struct CpeaMMIOState {
    SysBusDevice parent_obj;

    // Memory Region declaration?
    qemu_irq *irq;          /* Made pointer to dynamically change # IRQs that can be raised. */
};


struct CpeaIRQDriverState {
    SysBusDevice parent_obj;
    
    qemu_irq *irq;          /*  */
};

#endif /* CPEA_H_ */
