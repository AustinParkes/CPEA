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

static MMIO_handle *findMod(uint64_t, MMIO_handle**);  // Find peripheral module accessed in callback. 

// Callback for writing to mmio region
static void mmio_write(void *opaque, hwaddr addr,
                      uint64_t val, unsigned size)
{
    return;
}   

// Callback for reading from mmio region
// TODO: Could only issue callbacks for the registers defined in TOML file to save resources. I think mmio_ops lets you do that.
static uint64_t mmio_read(void *opaque, hwaddr addr,
                      unsigned size)
{
    ARMv7MState *armv7m;            // Holds CPU state
    uint32_t PC;                    // program counter
	uint32_t SR_temp;               // Temporary SR holding register
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
    for (int i=0; i < 16; i++){
        printf("Reg%d: 0x%x\n", i, armv7m->cpu->env.regs[i]);
    }
    /*
        Register Handling
        Determine if we are accessing DR or SR: Handle accordingly. Otherwise return 0.
        
        SR: Determine if there is an instance or not and act accordingly
        DR: Return 0 for now. Ideally, would fuzz in future.
        CR: Return 0 because CRs are ignored.
        
    */

    /*
    
        TODO:
        Logic:
        1) [x] Find the correct register being accessed by searching register addresses and matching with access address.
        2) [x] Determine if SR or DR access to know which to handle. (CRs ignored)
        3) [x] Return appropriate value.
        
        API:
        1) [p] Find a replacement for uc_reg_read() to read off PC.
               - See Problems 2)
               
        Problems:
        1) This callback seems to be issued when an MMIO address is loaded, but not exactly when it is accessed.
           (e.g.) ldr r3, 0x40064006 will issue callback, but 
                  ldr r3, [0x40064006] does not. 
                  
                  
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
	            
	                // Check if SR instance matches PC address.  
	                if (SR_INSTANCE[index]->PROG_ADDR == PC){ 
	                    SR_temp = periphx->SR[addr_i];
	                    SR_bit = SR_INSTANCE[index]->BIT;
	                    SR_val = SR_INSTANCE[index]->VAL;
	                    if (SR_val == 1)
	                        SET_BIT(SR_temp, SR_bit);
	                    else
	                        CLEAR_BIT(SR_temp, SR_bit);
	                    printf("SR_inst: 0x%x\n", SR_temp);
	                    // TODO: A single SR check may require more than 1 instance, might be a good idea to 
	                    //       allow someone to apply multiple for a single access point. 
	                    return SR_temp;    
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
    ARMv7MState *armv7m;    // To access Cortex-M CPU           
    DeviceState *cpu_dev;   // To create CPU device  
    //MachineClass *mc = MACHINE_GET_CLASS(machine);
    
    cpu_dev = qdev_new(TYPE_ARMV7M);      // Create ARMv7m device
    armv7m = ARMV7M(cpu_dev);             // To pass CPU state to callback     
    
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
    
    memory_region_init_io(mmio, NULL, &mmio_ops, (void *)armv7m, "mmio", 
                          MMIO_SIZE);
    
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
    
    
    qdev_prop_set_string(cpu_dev, "cpu-type", ARM_CPU_TYPE_NAME("cortex-m4"));
    qdev_prop_set_bit(cpu_dev, "enable-bitband", true);
    
    // Add system memory to device? So that it knows our memory make up?
    object_property_set_link(OBJECT(cpu_dev), "memory",
                             OBJECT(get_system_memory()), &error_abort);
                             
    /* This will exit with an error if bad cpu_type */   
    sysbus_realize_and_unref(SYS_BUS_DEVICE(cpu_dev), &error_fatal);
     
    armv7m_load_kernel(ARM_CPU(first_cpu), machine->kernel_filename,
                       FLASH_SIZE);
                    
    // Parse TOML configurations                   
    emuConfig();                     
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

// See MachineClass detailed description in 'include/hw/boards.h'
static void cpea_machine_init(MachineClass *mc){
    
    mc->desc = "CPEA Generic Machine";
    mc->is_default = true;                  
    mc->init = cpea_init;
    mc->default_cpu_type = ARM_CPU_TYPE_NAME("cortex-m4");
    mc->default_ram_size = 0.5 * GiB;   
       
}

// Macro defined in 'include/hw/boards.h.' 
// Generates TypeInfo for our Machine object, initializes a MachineClass object for us, and registers this type. 
DEFINE_MACHINE("cpea", cpea_machine_init); 

/*
static void cpea_machine_init_class_init(ObjectClass *oc, void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);
    cpea_machine_init(mc);
}

static const TypeInfo cpea_machine_init_typeinfo = {
    .name       = MACHINE_TYPE_NAME("cpea")
    .parent     = TYPE_MACHINE,
    .class_init = cpea_machine_init_class_init,
};

static void cpea_machine_init_register_types(void)
{
    type_register_static(&cpea_machine_init_typeinfo);
}
type_init(cpea_machine_init_register_types)
*/
