/*
 *
 * CPEA's Configurable Board 
 * Written by Austin Parkes
 * 
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


/* 
    SYSCLK frequency: Chose a value that works.
*/
#define SYSCLK_FRQ 120000000ULL

static CpeaMMIO *findMod(uint64_t, CpeaMMIO**);  // Find peripheral module accessed in callback. 

// Callback for writes to mmio region
// TODO: Log data that is written to registers.
static void mmio_write(void *opaque, hwaddr addr,
                      uint64_t val, unsigned size)
{
    return;
}   

// Callback for reads from mmio region
/* TODO: 1) Could only issue callbacks for the registers defined in TOML file to optimize performance. 
            mmio_ops might let you restrict register addresses.
            
         2) Could also only init memory regions based on registers defined in TOML.

         
*/
static uint64_t mmio_read(void *opaque, hwaddr addr,
                      unsigned size)
{
    ARMv7MState *armv7m;            // Holds CPU state
    MMIOkey MMIOReg;               // MMIO register accessed
    uint32_t PC;                    // program counter
	int SR_bit;                     // SR bit location to write to (0-31)
	int SR_val;                     // Hold SR bit value (1 or 0)
	int addr_i;                     // Index registers' addresses
	int index;                      // Index for SR instances
 
    armv7m = (ARMv7MState *)opaque;     // Obtain ARMv7M state
	
    // Compute absolute addr from offset
    hwaddr reg_addr = 0x40000000 + addr;
    
    // Get the MMIO register data associated with this IO address
    /*
        TODO: This hangs forever on IO addresses the user never configured
              because it loops the hash table until it finds a match. 
              We NEED to be able to quickly ignore IO addresses that 
              aren't in the hash table. 
              Might be able to init IO regions ONLY for IO addresses the user
              configured. That way, we'd always find a match. 
    */
    /*
    MMIOReg = LookupHashAddr((uint32_t)reg_addr);
    if (!MMIOReg.AddrKey){
        printf("ERROR\n");
        fprintf(stderr, "ERROR: Failed to look up IO address in Hash Table\n");
        exit(1);    
    }
    
    printf("AddrKey:%d\n", MMIOReg.AddrKey);
    printf("MMIOIndex%d\n", MMIOReg.MMIOIndex);
    printf("RegType:%d\n", MMIOReg.RegType);
    printf("RegIndex%d\n", MMIOReg.RegIndex);
    */
    CpeaMMIO *periphx = NULL;	// Points to the peripheral mmio accessed. 
    
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
    
    // Find register being accessed and handle according to type (DR, CR or SR)
    for (addr_i=0; addr_i < MAX_SR; addr_i++){
    
        // Search DRs for match
        if (addr_i < 2){
            if (reg_addr == periphx->DR_ADDR[addr_i]){
                return 0;   // TODO: Ideally would provide some sort of fuzz data here that depends on the peripheral.
            } 
        }
        
        // Search SRs for match
        // TODO: Turn into a function for portability.
        if (reg_addr == periphx->SR_ADDR[addr_i]){
            
            // SR instance doesn't exist. Return register value
            if (!periphx->SR_INST){
                return periphx->SR[addr_i];
            }
    
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
		        //printf("PC_inst: 0x%x\n", PC);	  
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
	                        
	                    //printf("SR_inst: 0x%x\n", periphx->SR[addr_i]);    
	                    //printf("SR_inst: 0x%x\n", SR_temp);
	                    
	                    return periphx->SR[addr_i];
	                    //return SR_temp;    
	                } 
	            }
	            
	            // No instance at accessed address, so return register value.
	            //printf("SR_no_inst: 0x%x\n", periphx->SR[addr_i]);
	            return periphx->SR[addr_i];   
            }      
        }   // Would be end of functionS
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

static void cpea_irq_driver_init(Object *obj)
{
    //DeviceState *dev = DEVICE(obj);


}

static void cpea_mmio_init(Object *obj)
{    
    //DeviceState *dev = DEVICE(obj);
    
    //  
    
    printf("MMIO Device Init!\n");
}

static void cpea_init(MachineState *machine)
{
    CpeaMachineState *cms = CPEA_MACHINE(machine);
    DeviceState *cpu_dev;   
    ARMv7MState *armv7m;                           
    
    MemoryRegion *flash = g_new(MemoryRegion, 1);
    MemoryRegion *sram = g_new(MemoryRegion, 1);
    MemoryRegion *mmio = g_new(MemoryRegion, 1);
    MemoryRegion *system_memory = get_system_memory();
    
    char arm_cpu_model[30];
    
    // Default Core 
    strcpy(cms->cpu_model, "cortex-m4");
    cms->has_bitband = true;
    cms->num_irq = 480;             // Max out IRQ lines. Reducing this has performance benefit when iterating through IRQs.
    
    // Default Memory
    cms->flash_base = 0x0;
    cms->flash_size = 32768000;
    cms->sram_base = 0x1fff0000;
    cms->sram_size = 0x02000000;    // Max out SRAM. Any larger and we dip into potential bitband region. Was 256000
    cms->sram_base2 = 0;
    cms->sram_size2 = 0;
    cms->sram_base3 = 0;
    cms->sram_size3 = 0;    
         
    // Parse user configurations                  
    cms = emuConfig(cms);
    
    cpu_dev = qdev_new(TYPE_ARMV7M);
    armv7m = ARMV7M(cpu_dev); 
    
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
    // TODO: Should just init the regions for which the user configures. 
    memory_region_init_io(mmio, NULL, &mmio_ops, (void *)armv7m, "mmio", 
                          0x20000000);
    
    memory_region_add_subregion(system_memory, 0x40000000, mmio);                        
    
    
        
    // For systick_reset. Required in ARMv7m
    system_clock_scale = NANOSECONDS_PER_SECOND / SYSCLK_FRQ;
    
    /* Configure CPU */
    strcpy(arm_cpu_model, cms->cpu_model);
    strcat(arm_cpu_model, "-arm-cpu");              // Replaces ARM_CPU_TYPE_NAME(name) macro. 
    
    qdev_prop_set_string(cpu_dev, "cpu-type", arm_cpu_model);    
    qdev_prop_set_bit(cpu_dev, "enable-bitband", cms->has_bitband);   
    qdev_prop_set_uint32(cpu_dev, "num-irq", cms->num_irq);
       
    object_property_set_link(OBJECT(cpu_dev), "memory",
                             OBJECT(get_system_memory()), &error_abort);
                             
    /* This will exit with an error if bad cpu_type */   
    sysbus_realize_and_unref(SYS_BUS_DEVICE(cpu_dev), &error_fatal);
     
    armv7m_load_kernel(ARM_CPU(first_cpu), machine->kernel_filename,
                       cms->flash_size);
                                       
}

/* 
    Search for the accessed peripheral module
    
    Returns NULL if none found. 

*/
static CpeaMMIO *findMod(uint64_t address, CpeaMMIO** periph){

	int mod_i;		// Index for peripheral module
	CpeaMMIO *periphx = *periph;
	
    // Determine which MMIO module the accessed address belongs to.     
    for (mod_i=0; mod_i < mmio_total; mod_i++){
    
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

// Compute Index from an IO address
int HashAddr(uint32_t IOaddr)
{
    int index;
    uint16_t pair1, pair2, pair3, pair4; 
    printf("IO addr: %u\n", IOaddr);
    // Folding method
    pair1 = IOaddr >> (6*4);
    pair2 = IOaddr >> (4*4);
    pair2 = pair2 & (0xff);
    pair3 = IOaddr >> (2*4);
    pair3 = pair3 & (0xff);
    pair4 = IOaddr & (0xff);

    index = (pair1 + pair2 + pair3 + pair4)%HASH_SIZE;
    printf("Hashed Index: %x\n", index);

    return index;
}

// Fill hash table with key-data pair.
void FillHashTable(uint32_t key, int mod_i, int reg_type, int reg_i)
{
    int HashIndex;          // Index from hashed IO address
    
    // Get hash table index
    HashIndex = HashAddr(key);
					
    // Index available. Place data.
    if (!MMIOHashTable[HashIndex].AddrKey){
	    MMIOHashTable[HashIndex].AddrKey = key;
		MMIOHashTable[HashIndex].MMIOIndex = mod_i;  
		MMIOHashTable[HashIndex].RegType = reg_type;
		MMIOHashTable[HashIndex].RegIndex = reg_i;  
	}
    // Index unavailable. Find a new one using open addressing. (load factor assumed to be very low)
    else{
					
	    // Search for open spot
	    while(MMIOHashTable[HashIndex].AddrKey){
		    HashIndex += 3;
			HashIndex = HashIndex % HASH_SIZE;	
		    if (!MMIOHashTable[HashIndex].AddrKey){
			    MMIOHashTable[HashIndex].AddrKey = key;
			    MMIOHashTable[HashIndex].MMIOIndex = mod_i;  
			    MMIOHashTable[HashIndex].RegType = reg_type;
			    MMIOHashTable[HashIndex].RegIndex = reg_i;  
			}				    
		}
	}
}

MMIOkey LookupHashAddr(uint32_t addr)
{
    int HashIndex;
    int AddrKey;
    HashIndex = HashAddr(addr);
    
    AddrKey = MMIOHashTable[HashIndex].AddrKey;
    // Match found. Return MMIO data.
    if (addr == AddrKey)
        return MMIOHashTable[HashIndex];

    // No match, search for a match.
    else{
        while(addr != AddrKey){
            HashIndex += 3;
            HashIndex = HashIndex % HASH_SIZE;
            AddrKey = MMIOHashTable[HashIndex].AddrKey;
            if (addr == AddrKey)
                return MMIOHashTable[HashIndex];   
        }
    }    
 
    // Failure
    MMIOHashTable[HashIndex].AddrKey = 0;
    return MMIOHashTable[HashIndex];   
}

// IRQ Firing Device
static void cpea_irq_driver_class_init(ObjectClass *klass, void *data)
{
    //DeviceClass *dc = DEVICE_CLASS(klass);
    // Anything need to go here?
}

static const TypeInfo cpea_irq_driver_info = {
    .name = TYPE_CPEA_IRQ_DRIVER,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(CpeaIRQDriverState),
    .instance_init = cpea_irq_driver_init,
    .class_init    = cpea_irq_driver_class_init,
};

// mmio Device
static void cpea_mmio_class_init(ObjectClass *klass, void *data)
{
    //DeviceClass *dc = DEVICE_CLASS(klass);
    // Anything need to go here?    
}

static const TypeInfo cpea_mmio_info = {
    .name = TYPE_CPEA_MMIO,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(CpeaMMIOState),
    .instance_init = cpea_mmio_init,
    .class_init    = cpea_mmio_class_init,
};


// CPEA Device   
static void cpea_class_init(ObjectClass *oc, void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);
    
    mc->desc = "CPEA Generic Machine";
    mc->is_default = true;                  
    mc->init = cpea_init;          
}  

static const TypeInfo cpea_info = {
    .name       = TYPE_CPEA_MACHINE,
    .parent     = TYPE_MACHINE,
    .instance_size = sizeof(CpeaMachineState),
    .class_init = cpea_class_init,
};

static void cpea_machine_init(void){
    type_register_static(&cpea_info);
    type_register_static(&cpea_mmio_info);
    type_register_static(&cpea_irq_driver_info);
}  
type_init(cpea_machine_init);
