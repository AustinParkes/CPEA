/*
 * CPEA's Configurable Board 
 */

#include <stdio.h>
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/units.h"
#include "hw/arm/armv7m.h"
#include "hw/boards.h"
#include "hw/qdev-properties.h"
#include "hw/arm/boot.h"
#include "exec/address-spaces.h"
#include "exec/memory.h"
#include "cpea/emulatorConfig.h"
#include "hw/arm/cpea.h"
#include "qom/object.h"



/* SYSCLK frequency: Chose a value that works.
   TODO: Make configurable? Don't see a need yet. Just care about FW execution. 
*/
#define SYSCLK_FRQ 120000000ULL

static MMIO_handle *findMod(uint64_t, MMIO_handle**);  // Find peripheral module accessed in callback. 

// Callback for writes to mmio region
// TODO: Log data that is written to registers.
static void mmio_write(void *opaque, hwaddr addr,
                      uint64_t val, unsigned size)
{
    return;
}   

// Callback for reads from mmio region
/* TODO: Could only issue callbacks for the registers defined in TOML file to optimize performance. 
         mmio_ops might let you restrict register addresses.

*/
static uint64_t mmio_read(void *opaque, hwaddr addr,
                      unsigned size)
{
    ARMv7MState *armv7m;            // Holds CPU state
    uint32_t PC;                    // program counter
	//uint32_t SR_temp;               // Temporary SR holding register
	int SR_bit;                     // SR bit location to write to (0-31)
	int SR_val;                     // Hold SR bit value (1 or 0)
	int addr_i;                     // Index registers' addresses
	int index;                      // Index for SR instances
 
    armv7m = (ARMv7MState *)opaque;     // Obtain ARMv7M state
	
    // Compute absolute addr from offset
    hwaddr reg_addr = 0x40000000 + addr;
    
    MMIO_handle *periphx = NULL;	// Points to the peripheral mmio accessed. 
    
    // Determine if we are accessing a peripheral we mapped.  
    periphx = findMod(reg_addr, &periphx);
    if (periphx == NULL)
        return -1;
        
    /*
    // Print the current state of the ARM core. (R15 is the most recent PC, not the current.)    
    for (int i=0; i < 16; i++){
        printf("Reg%d: 0x%x\n", i, armv7m->cpu->env.regs[i]);
    }
    */
    
    // Find register being accessed and handle according to type (DR or SR)
    for (addr_i=0; addr_i < MAX_SR; addr_i++){
    
        // Search DRs for match
        if (addr_i < 2){
            if (reg_addr == periphx->DR_ADDR[addr_i]){
                return 0;   // TODO: Ideally would provide some sort of fuzz data here that depends on the peripheral.
            } 
        }
        
        // Search SRs for match
        if (reg_addr == periphx->SR_ADDR[addr_i]){
            
            // SR instance doesn't exist. Return register value
            if (!periphx->SR_INST){
                return periphx->SR[addr_i];
            }
    
            // TODO: Need to read PC with QEMU API
            // SR instance exists
	        else {	
	            /* 
	                NOTE: 
	                This environment (env) contains the LAST executed address and the results from that.
	                So, R15 is not up to date with the current PC, but R0-R14 are up to date.
	                Specifically, the env contains the last PC, not the current. It also contains the register results from the last PC execution.
	                
	                Problem:
	                We need the current PC. One way to remedy is to check if we are within a byte of the desired PC.	            
	            */
	            PC = armv7m->cpu->env.regs[15];     // Get program counter	
		        //uc_reg_read(uc, UC_ARM_REG_PC, &PC);
		        printf("PC_inst: 0x%x\n", PC);	  
	            // Loop SR instances & look for match
	            for (index = 0; index < inst_i; index++){
	                
	                // HACK: We only have access to the previous PC. Check if SR instance is within a byte of PC. 
	                if (SR_INSTANCE[index]->INST_ADDR >= PC && SR_INSTANCE[index]->INST_ADDR <= PC + 4){ 
	                    //SR_temp = periphx->SR[addr_i];
	                    SR_bit = SR_INSTANCE[index]->BIT;
	                    SR_val = SR_INSTANCE[index]->VAL;
	                    if (SR_val == 1)
	                        SET_BIT(periphx->SR[addr_i], SR_bit);
	                        //SET_BIT(SR_temp, SR_bit);
	                    else
	                        CLEAR_BIT(periphx->SR[addr_i], SR_bit);
	                        //CLEAR_BIT(SR_temp, SR_bit);
	                        
	                    printf("SR_inst: 0x%x\n", periphx->SR[addr_i]);    
	                    //printf("SR_inst: 0x%x\n", SR_temp);
	                    
	                    return periphx->SR[addr_i];
	                    //return SR_temp;    
	                } 
	            }
	            
	            // No instance at accessed address, so return register value.
	            printf("SR_no_inst: 0x%x\n", periphx->SR[addr_i]);
	            return periphx->SR[addr_i];   
            }      
        }
    }

    // Return 0 for unregistered MMIO  
    return 0;
}                   

// Specify callback functions for mmio
static const MemoryRegionOps mmio_ops = {
    .read = mmio_read,
    .write = mmio_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .impl.min_access_size = 1,   
    .impl.max_access_size = 4,
};


static void cpea_init(MachineState *machine)
{
    CpeaMachineState *cms = CPEA_MACHINE(machine);
    DeviceState *cpu_dev;   
    ARMv7MState *armv7m;          
         
    cpu_dev = qdev_new(TYPE_ARMV7M);      // Create ARMv7m cpu device
    armv7m = ARMV7M(cpu_dev);             // Get armv7m State: To pass CPU state to callback     
    
    MemoryRegion *flash = g_new(MemoryRegion, 1);
    MemoryRegion *sram = g_new(MemoryRegion, 1);
    MemoryRegion *mmio = g_new(MemoryRegion, 1);
    MemoryRegion *system_memory = get_system_memory();
    
    char arm_cpu_model[30];
    
    // Default Core 
    strcpy(cms->cpu_model, "cortex-m4");
    cms->has_bitband = true;
    cms->num_irq = 57;
    
    // Default Memory
    cms->flash_base = 0x0;
    cms->flash_size = 32768000;
    cms->sram_base = 0x1fff0000;
    cms->sram_size = 256000;
    cms->sram_base2 = 0;
    cms->sram_size2 = 0;
    cms->sram_base3 = 0;
    cms->sram_size3 = 0;    
         
    // Handle all TOML configurations, possibly modifing default configs.                   
    cms = emuConfig(cms);
    
    // Init mem regions, and add them to system memory      
    memory_region_init_rom(flash, NULL, "flash", cms->flash_size,
                           &error_fatal);
                     
    memory_region_add_subregion(system_memory, cms->flash_base, flash);

    memory_region_init_ram(sram, NULL, "sram", cms->sram_size,
                           &error_fatal);
                                               
    memory_region_add_subregion(system_memory, cms->sram_base, sram);                                                  
     
    if (cms->sram_size2){
        MemoryRegion *sram2 = g_new(MemoryRegion, 1);
        memory_region_init_ram(sram2, NULL, "sram2", cms->sram_size2,
                               &error_fatal);
                                               
        memory_region_add_subregion(system_memory, cms->sram_base2, sram2);
    }
 
    if (cms->sram_size3){
        MemoryRegion *sram3 = g_new(MemoryRegion, 1);
        memory_region_init_ram(sram3, NULL, "sram3", cms->sram_size3,
                               &error_fatal);
                                               
        memory_region_add_subregion(system_memory, cms->sram_base3, sram3);
    }
    
    memory_region_init_io(mmio, NULL, &mmio_ops, (void *)armv7m, "mmio", 
                          0x20000000);
    
    memory_region_add_subregion(system_memory, 0x40000000, mmio);                        
        
    // For systick_reset. Required in ARMv7m
    system_clock_scale = NANOSECONDS_PER_SECOND / SYSCLK_FRQ;
    
    // Create ARMv7m "armv7m" CPU of model cortex-m4
    // object_initialize_child(OBJECT(), "armv7m", &cps->armv7m, TYPE_ARMV7M);    
    // cpu_dev = DEVICE(&cps->armv7m);         // Get device from armv7m. Replaces line below.       
     
    /* TODO: Need to set the number of IRQs. (Can I max this out? Think not ...) Not sure what happens when we set IRQs in qemu.
       e.g: qdev_prop_set_uint32(cpu-dev, "num-irq", 96);
       Guess is we need to set number of IRQs that the MCU supports. Usually this isn't hard to analyze in a binary. 
       Can add a configuration for this in the toml file.   
    */
    
    strcpy(arm_cpu_model, cms->cpu_model);
    strcat(arm_cpu_model, "-arm-cpu");              // Replaces ARM_CPU_TYPE_NAME(name) macro. 
    
    qdev_prop_set_string(cpu_dev, "cpu-type", arm_cpu_model);    
    qdev_prop_set_bit(cpu_dev, "enable-bitband", cms->has_bitband);
    
    // Can we always just max this out? (num-irq here should just include external IRQs. However, NVICState::num_irq counts ALL exceptions. 480 max for # external intr. in armv7m)
    qdev_prop_set_uint32(cpu_dev, "num-irq", cms->num_irq);
    
    // Write system memory to device's memory through it's "memory" property
    object_property_set_link(OBJECT(cpu_dev), "memory",
                             OBJECT(get_system_memory()), &error_abort);
                             
    /* This will exit with an error if bad cpu_type */   
    sysbus_realize_and_unref(SYS_BUS_DEVICE(cpu_dev), &error_fatal);
     
    armv7m_load_kernel(ARM_CPU(first_cpu), machine->kernel_filename,
                       cms->flash_size);
                                       
}

/* 
    Search for a peripheral module that has a register address which
    matches the accessed address.
    
    Returns NULL if none found. 

*/
static MMIO_handle *findMod(uint64_t address, MMIO_handle** periph){

	int mod_i;		// Index for peripheral module
	MMIO_handle *periphx = *periph;
	
    // Determine which MMIO module the accessed address belongs to.     
    for (mod_i=0; mod_i < mod_count; mod_i++){
    
    	if (!MMIO[mod_i]){
    		printf("Error accessing MMIO%d in mmio_read callback", mod_i);	
    		exit(1);
    	} 
    	 	
    	// Get the correct peripheral module. (Does accessed addr match this module?)	 		
		if (address >= MMIO[mod_i]->minAddr && address <= MMIO[mod_i]->maxAddr){
			periphx = MMIO[mod_i];
    		break;
    	}    		
    }

	return periphx;

}  

// NOTE: Don't think you can get a State from a Class.    
static void cpea_class_init(ObjectClass *oc, void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);
    
    mc->desc = "CPEA Generic Machine";
    mc->is_default = true;                  
    mc->init = cpea_init; 
          
}  

// TODO: Need instance and class sizes of our CpeaMachineState and CpeaMachineClass
static const TypeInfo cpea_info = {
    .name       = TYPE_CPEA_MACHINE,
    .parent     = TYPE_MACHINE,
    .instance_size = sizeof(CpeaMachineState),
    .class_init = cpea_class_init,
};

static void cpea_machine_init(void){
    type_register_static(&cpea_info);
}  
type_init(cpea_machine_init);
