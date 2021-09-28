/*
 * CPEA's Configurable Board 
 */

#include <stdio.h>
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/units.h"
#include "cpu.h"
#include "hw/arm/armv7m.h"
#include "hw/boards.h"
#include "hw/qdev-properties.h"
#include "hw/arm/boot.h"
#include "exec/address-spaces.h"

// Address map for K64 32-bit mcu 
#define FLASH_BASE 0
#define FLASH_SIZE 0x1FFF0000

#define SRAM_BASE 0x1FFF0000
#define SRAM_SIZE 0x2000ffff

#define MMIO_BASE 0x40000000
#define MMIO_SIZE 0x20000000

#define RAM1_BASE 0x60000000
#define RAM1_SIZE 0x20000000

#define RAM2_BASE 0x80000000
#define RAM2_SIZE 0x20000000

#define DEVICE1_BASE 0xA0000000
#define DEVICE1_SIZE 0xBF000000

#define DEVICE2_BASE 0xC0000000
#define DEVICE2_SIZE 0x20000000

#define SYSTEM_BASE 0xE0000000
#define SYSTEM_SIZE 0x20000000 

#define SYSCLK_FRQ 120000000ULL



static void mmio_write(void *opaque, hwaddr addr,
                      uint64_t val, unsigned size)
{
    return;
}   

static uint64_t mmio_read(void *opaque, hwaddr addr,
                      unsigned size)
{
    return 0;
}                   

// Specify callback functions for mmio
static const MemoryRegionOps mmio_ops = {
    .read = mmio_read,
    .write = mmio_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

// TODO TODO TODO: Fix SRAM/FLASH Regions. Acknowledge the firmware file size too... (extends beyond SRAM start ... which is bad)
//                 ALSO, check the parameter that armv7_load_kernel takes in. We give it flash size, but maybe we could give it our own file size. 


// What is DeviceState? Apart of Qdev API. Probably best to look there.
static void cpea_init(MachineState *machine){
     
    //ARMCPU *cpu;            
    DeviceState *dev;    // Going to create CPU from this
        
    // May not need this, but can access our particular machine this way.
    // Get the machine we instantiated earlier.
    //MachineClass *mc = MACHINE_GET_CLASS(machine);
    
    MemoryRegion *flash = g_new(MemoryRegion, 1);
    MemoryRegion *sram = g_new(MemoryRegion, 1);
    MemoryRegion *mmio = g_new(MemoryRegion, 1);
    MemoryRegion *system_memory = get_system_memory();
    
    // Init mem regions, and add them to system memory
    memory_region_init_rom(flash, NULL, "flash", FLASH_SIZE,
                           &error_fatal);
                     
    memory_region_add_subregion(system_memory, FLASH_BASE, flash);

    memory_region_init_ram(sram, NULL, "sram", SRAM_SIZE,
                           &error_fatal);
                                               
    memory_region_add_subregion(system_memory, SRAM_BASE, sram);                                                  
     
    memory_region_init_io(mmio, NULL, &mmio_ops, NULL, "mmio", 
                          MMIO_SIZE);
    
    memory_region_add_subregion(system_memory, 0x40000000, mmio);                        
        
    // For systick_reset. Required in ARMv7m
    system_clock_scale = NANOSECONDS_PER_SECOND / SYSCLK_FRQ;

    // Create ARMv7m CPU of model cortex-m4
    dev = qdev_new(TYPE_ARMV7M);
    qdev_prop_set_string(dev, "cpu-type", ARM_CPU_TYPE_NAME("cortex-m4"));
    //qdev_prop_set_bit(dev, "enable-bitband", true);
    
    // Add system memory to device? So that it knows our memory make up?
    object_property_set_link(OBJECT(dev), "memory",
                             OBJECT(get_system_memory()), &error_abort);
                             
    /* This will exit with an error if bad cpu_type */   
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
    
    // Will almost certainly need this in the future. Loads kernel and 
    // armv7m_load_kernel(ARM_CPU(first_cpu), ms->kernel_filename, flash_size);    
    armv7m_load_kernel(ARM_CPU(first_cpu), machine->kernel_filename,
                       FLASH_SIZE);
                           
}


// See MachineClass detailed description in 'include/hw/boards.h'
static void cpea_machine_init(MachineClass *mc){
    
    mc->desc = "CPEA Generic Machine";
    mc->is_default = true;                  
    mc->init = cpea_init;
    mc->default_cpu_type = ARM_CPU_TYPE_NAME("cortex-m4");
    mc->default_ram_size = 0.5 * GiB;       //(0x20000000)   
       
}

// Macro defined in 'include/hw/boards.h.' 
// Generates TypeInfo for our Machine object, initializes a MachineClass object for us, and registers this type. 
DEFINE_MACHINE("cpea", cpea_machine_init); 

