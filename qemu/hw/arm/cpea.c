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
#include "hw/qdev-properties.h"
#include "hw/arm/boot.h"
#include "exec/address-spaces.h"
#include "exec/memory.h"
#include "hw/arm/armv7m.h"
#include "cpea/callbacks.h"
#include "hw/arm/cpea.h"


/* 
    SYSCLK frequency: Chose a value that works.
    This would preferably be a configurable option since this would influence the systick timer's
    ability to trigger interrupts. I also believe this is the CPU's clocking freq.
*/
#define SYSCLK_FRQ 120000000ULL

// Callback for writes to mmio region
static void mmio_write(void *opaque, hwaddr addr,
                      uint64_t val, unsigned size)
{

    int match;                      // Flag set if register type found
	int DR_i = 0;                   // Data Register Index
	int CR_i = 0;                   // Control Register Index
	int SR_i = 0;                   // Status Register Index
	
    hwaddr reg_addr = 0x40000000 + addr;   
    CpeaMMIO *MMIO = NULL;
    match = 0;

    MMIO = findMod(reg_addr, &MMIO);
    if (MMIO == NULL)
        return;

    // Determine register type accessed (DR, CR, SR)    
    while (!match){
        match = 0;
                   
        // Search DRs
        if (MMIO->DR_ADDR[DR_i] && DR_i != MAX_DR){
               
            // DR Write
            if (reg_addr ==  MMIO->DR_ADDR[DR_i]){

                if ( (emulateIO[MMIO->periphID].DRwrite) != NULL )
                    (*emulateIO[MMIO->periphID].DRwrite)(MMIO, val);
                                        
                match = 1; 
                                  
            }
            DR_i++;
        }      
          
        // Search CRs
        else if (MMIO->CR_ADDR[CR_i] && CR_i != MAX_CR){
            
            // CR Write
            if (reg_addr ==  MMIO->CR_ADDR[CR_i]){               
                MMIO->CR[CR_i] = (uint32_t)val;                                
                if ( (emulateIO[MMIO->periphID].CRwrite) != NULL )
                    (*emulateIO[MMIO->periphID].CRwrite)(MMIO, reg_addr, val);           
                match = 1;
            }        
            CR_i++;
        }
    
        else if (MMIO->SR_ADDR[SR_i] && SR_i != MAX_SR){        
            if (reg_addr ==  MMIO->SR_ADDR[SR_i]){
                MMIO->SR[SR_i] = (uint32_t)val;
                if ( (emulateIO[MMIO->periphID].SRwrite) != NULL )
                    (*emulateIO[MMIO->periphID].SRwrite)(MMIO, val);                           
                match = 1;
            }        
            SR_i++;
        }
        
        // No matches found.
        else{
            break;
        } 
    }
    
}   

static uint64_t mmio_read(void *opaque, hwaddr addr,
                      unsigned size)
{

    ARMv7MState *armv7m;            // Holds CPU state
    //uint32_t data;                  // Data read from FW
    uint64_t r;                     // Return value for register reads
    uint32_t PC;                    // program counter
	int SR_bit;                     // SR bit location to write to (0-31)
	int SR_val;                     // Hold SR bit value (1 or 0)
	int index;                      // Index for SR instances             
    int match;                      // Flag set if register type found
	int DR_i = 0;                   // Data Register Index
	int CR_i = 0;                   // Control Register Index
	int SR_i = 0;                   // Status Register Index
    //int rxfifo_size;            

    armv7m = (ARMv7MState *)opaque;
    
    hwaddr reg_addr = 0x40000000 + addr;
    
    CpeaMMIO *MMIO = NULL;
    match = 0;
    
    MMIO = findMod(reg_addr, &MMIO);
    if (MMIO == NULL)
        return 0;

    // Determine register type accessed (DR, CR, DR). Handle accordingly. 
    while (!match){
        match = 0;
                   
        // Search DRs
        if (MMIO->DR_ADDR[DR_i] && DR_i != MAX_DR){
               
            // DR Read
            if (reg_addr ==  MMIO->DR_ADDR[DR_i]){
                if ( (emulateIO[MMIO->periphID].DRread) != NULL )
                    r = (*emulateIO[MMIO->periphID].DRread)(MMIO);                
                match = 1;                   
            }
            DR_i++;
        }      
          
        // Search CRs
        else if (MMIO->CR_ADDR[CR_i] && CR_i != MAX_CR){
            
            // CR Read
            if (reg_addr ==  MMIO->CR_ADDR[CR_i]){                 
                if ( (emulateIO[MMIO->periphID].CRread) != NULL )
                    r = (*emulateIO[MMIO->periphID].CRread)(MMIO);
                else
                    r = MMIO->CR[CR_i];                                                             
                match = 1;
            }        
            CR_i++;
        }
    
        // Search SRs
        // TODO: Probably want to neaten this up and make more readable
        else if (MMIO->SR_ADDR[SR_i] && SR_i != MAX_SR){
        
            // SR Read
            // TODO: Probably want to add 
            if (reg_addr ==  MMIO->SR_ADDR[SR_i]){  
                         
                // SR instance doesn't exist.
                if (!MMIO->SR_INST){
                    r = MMIO->SR[SR_i];
                }
                                
                // SR instance exists for this peripheral. 
                // Check if it's for the accessed address
                else{
                    /*
                        NOTE: PC is a instruction ahead when stepping through in GDB (e.g. would be 0x19f2 instead of 0x19f0 at that point)
	                          Need to take this into account for someone using GDB   
	                          
	                    NOTE: PC is an instruction behind right here.      
                    */
                    PC = armv7m->cpu->env.regs[15]; 
	                for (index = 0; index < inst_i; index++){
	                
	                    // HACK: We only have access to the previous PC. Check if SR instance is within a byte of PC. 
	                    if (SR_INSTANCE[index]->INST_ADDR >= PC && SR_INSTANCE[index]->INST_ADDR <= PC + 4){ 
	                        SR_bit = SR_INSTANCE[index]->BIT;
	                        SR_val = SR_INSTANCE[index]->VAL;
	                        if (SR_val == 1)
	                            SET_BIT(MMIO->SR[SR_i], SR_bit);
	                        else
	                            CLEAR_BIT(MMIO->SR[SR_i], SR_bit);	                    
	                    } 
	                }
	                r = MMIO->SR[SR_i];                                       
                }                    
                match = 1;
            }        
            SR_i++;
        }
        
        // No matches found.
        else{
            r = 0;
            break;
        } 
    }    

    return r;
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
    CpeaIRQDriverState *s = CPEA_IRQ_DRIVER(obj);
    
    int IRQcnt = 0;     // IRQ counter
    int mmio_i = 0;     // Current MMIO index
    int intr_i = 0;     // Current INTR index            
    
    if (IRQtotal){     
        s->irq = g_new(qemu_irq, IRQtotal);
        s->IRQn_list = (int *)malloc(sizeof(int) * IRQtotal);       
    }

    // Init output IRQ for each activated interrupt, in order.
    while(mmio_i < mmio_total){    	    
    	for (intr_i = 0; intr_i < MAX_INTR; intr_i++){
    	    if (MMIO[mmio_i]->INTR[intr_i]){
    	        s->IRQn_list[intr_i] = MMIO[mmio_i]->INTR[intr_i]->irqn;
    	        qdev_init_gpio_out(DEVICE(s), &s->irq[IRQcnt], 1);
    	        IRQcnt++;  
    	    } 
    	}
    	mmio_i++;            	               	        
    }           		
}

static void cpea_init(MachineState *machine)
{
    CpeaMachineState *cms = CPEA_MACHINE(machine);
    ARMv7MState *armv7m;
    DeviceState *cpu_dev;                            
    DeviceState *irq_driver;
    
    MemoryRegion *flash = g_new(MemoryRegion, 1);
    MemoryRegion *sram = g_new(MemoryRegion, 1);
    MemoryRegion *mmio = g_new(MemoryRegion, 1);
    MemoryRegion *system_memory = get_system_memory();
    
    // Used to init char front end
    Error *err;
    
    char arm_cpu_model[30];

    int mmio_i = 0;
    int intr_i = 0;
    int IRQcnt = 0;
    
    // Default Core 
    strcpy(cms->cpu_model, "cortex-m4");
    cms->has_bitband = true;
    cms->num_irq = 480;             // Max out IRQ lines.
    
    // Default Memory
    cms->flash_base = 0x0;
    cms->flash_size = 32768000;
    cms->sram_base = 0x1fff0000;
    cms->sram_size = 0x02000000;    // Max out SRAM. Any larger and we dip into potential bitband region.
    cms->sram_base2 = 0;
    cms->sram_size2 = 0;
    cms->sram_base3 = 0;
    cms->sram_size3 = 0;    
    
    // Parse user configurations                  
    cms = emuConfig(cms);
      
    // Init cpu device
    cpu_dev = qdev_new(TYPE_ARMV7M);
    //cms->armv7m = ARMV7M(cpu_dev);
    armv7m = ARMV7M(cpu_dev);
    
    // init irq device
    irq_driver = qdev_new(TYPE_CPEA_IRQ_DRIVER); 
    cms->irq_state = CPEA_IRQ_DRIVER(irq_driver);    
    
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
        
    memory_region_init_io(mmio, NULL, &mmio_ops, armv7m, "mmio", 
                          0x20000000);
    
    memory_region_add_subregion(system_memory, 0x40000000, mmio);                        
       
    // For systick_reset. Required in ARMv7m
    system_clock_scale = NANOSECONDS_PER_SECOND / SYSCLK_FRQ;
    
    /* Configure CPU */
    strcpy(arm_cpu_model, cms->cpu_model);
    strcat(arm_cpu_model, "-arm-cpu");
    
    qdev_prop_set_string(cpu_dev, "cpu-type", arm_cpu_model);    
    qdev_prop_set_bit(cpu_dev, "enable-bitband", cms->has_bitband);   
    qdev_prop_set_uint32(cpu_dev, "num-irq", cms->num_irq);
       
    object_property_set_link(OBJECT(cpu_dev), "memory",
                             OBJECT(get_system_memory()), &error_abort);
                             
    /* This will exit with an error if bad cpu_type */   
    sysbus_realize_and_unref(SYS_BUS_DEVICE(cpu_dev), &error_fatal);

    // Connect & save output IRQs in same order initialized.
    while (mmio_i < mmio_total){
    	for (intr_i = 0; intr_i < MAX_INTR; intr_i++){
    	    if (MMIO[mmio_i]->INTR[intr_i]){
    	        qdev_connect_gpio_out(DEVICE(irq_driver), 
                                      IRQcnt, 
                                      qdev_get_gpio_in(cpu_dev, cms->irq_state->IRQn_list[IRQcnt]));
                                                                                     
                MMIO[mmio_i]->INTR[intr_i]->irq = cms->irq_state->irq[IRQcnt];
                IRQcnt++;
    	    } 
    	}
    	mmio_i++;    
    }
    
    // XXX: Note limit is 4 serial_hds
    Chardev *chrdev;
    chrdev = serial_hd(0);

    // Search mmio for uart and assign a serial Chardev to UART's Charbackend
    // TODO: Wanna do this per interrupt in the future
    for (mmio_i = 0; mmio_i < mmio_total; mmio_i++){		
    	if (MMIO[mmio_i]->periphID == uartID){
    	    	
    	    //Assign guest's serial chardev to host's backend
            if (!qemu_chr_fe_init(&MMIO[mmio_i]->chrbe, chrdev, &err)){
                printf("Failed to init Serial Chardev\n");
                exit(1);
            } 
                
            // Set handlers for front-end 
            qemu_chr_fe_set_handlers(&MMIO[mmio_i]->chrbe, uart_can_receive, uart_receive,
                                    uart_event, NULL, MMIO[mmio_i], NULL, true);  
 
            // TODO: This break is here ONLY to loop once ... get rid of it 
            //       when we allow communication to become configurable                         	                                    
    	    break;   
    	} 
    }	     		
                        
    armv7m_load_kernel(ARM_CPU(first_cpu), machine->kernel_filename,
                       cms->flash_size);
                                       
}


CpeaMMIO *findMod(uint64_t address, CpeaMMIO** periph){

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


static void cpea_irq_driver_class_init(ObjectClass *klass, void *data)
{
    ;   // TODO: Get rid of this
}

static const TypeInfo cpea_irq_driver_info = {
    .name = TYPE_CPEA_IRQ_DRIVER,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(CpeaIRQDriverState),
    .instance_init = cpea_irq_driver_init,
    .class_init    = cpea_irq_driver_class_init,
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
    type_register_static(&cpea_irq_driver_info);
}  
type_init(cpea_machine_init);
