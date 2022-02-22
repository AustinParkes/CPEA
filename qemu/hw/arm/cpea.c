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
#include "hw/arm/cpea.h"


/* 
    SYSCLK frequency: Chose a value that works.
    This would preferably be a configurable option since this would influence the systick timer's
    ability to trigger interrupts. I also believe this is the CPU's clocking freq.
*/
#define SYSCLK_FRQ 120000000ULL


static void uart_update(CpeaMMIO *MMIO, int type, int mode)
{

    // User configured         
    uint32_t enabled_config;
    uint32_t level_config;
    
    // Emulated CR & SR
    uint32_t intr_enabled;
    uint32_t intr_level;
     
    // Interrupt level used in partial emulation 
    int level; 
      
    enabled_config = MMIO->interrupt->CR_enable[type];
    level_config = MMIO->interrupt->SR_set[type];
    
    intr_enabled = MMIO->CR[MMIO->interrupt->CR_i[type]];
    intr_level = MMIO->SR[MMIO->interrupt->SR_i[type]];
    
    level = MMIO->interrupt->level;
    
    /*
    // Testing 
    printf("user CR: 0x%x\n", enabled_config);
    printf("user SR: 0x%x\n", level_config);
    printf("emu  CR: 0x%x\n", intr_enabled);
    printf("emu  SR: 0x%x\n", intr_level); 
    */
       
    // Handle interrupt update according to type and mode
    switch (type){    
    case RXFF:
        switch (mode){
        case full: 
            // RXFF is enabled AND RXFF is set
            if (enabled_config & intr_enabled && level_config & intr_level)
                qemu_set_irq(MMIO->irq, 1);                  
           
            // Lower interrupt
            else
                qemu_set_irq(MMIO->irq, 0);

            break;        
        
        case partial:
            if (CHECK_BIT(level, type))
                qemu_set_irq(MMIO->irq, 1);
                
            // Lower interrupt    
            else
                qemu_set_irq(MMIO->irq, 0);    
            break;
        }                        
        break;
                    
    default:
        break;        
    }    
    
}

static void put_fifo(void *opaque, uint8_t value)
{

    CpeaMMIO *MMIO = (CpeaMMIO *)opaque;
    int head;
    int rxfifo_size;
    
    rxfifo_size = MMIO->uart->rxfifo_size;
    
    // Head is where we place data. tail is where we read data.
    head = MMIO->uart->tail + MMIO->uart->queue_count;
    
    if (head >= rxfifo_size)
        head -= rxfifo_size;

    //printf("head: %d\n", head);    
    MMIO->uart->rx_fifo[head] = value;
    MMIO->uart->queue_count++; 
         
    // Interrupt emulation is enabled 
    if (MMIO->interrupt){
         
        // RXFIFO interrupt is emulated  
        if (CHECK_BIT(MMIO->interrupt->enabled, RXFF)){            
            if (MMIO->uart->queue_count >= MMIO->interrupt->Trigger_val[RXFF]){           
                // Fully emulating RXFIFO Interrupt 
                if (!CHECK_BIT(MMIO->interrupt->partial, RXFF)){
                
                    // Set RXFF SR bit
                    MMIO->SR[MMIO->interrupt->SR_i[RXFF]] |= MMIO->interrupt->SR_set[RXFF];
                    uart_update(MMIO, RXFF, full);
                    
                }                                
                // Partially emulating RXFIFO Interrupt
                else{
                    SET_BIT(MMIO->interrupt->level, RXFF);
                    // Set RXFF SR bit, even if it isn't emulated
                    MMIO->SR[MMIO->interrupt->SR_i[RXFF]] |= MMIO->interrupt->SR_set[RXFF];
                    uart_update(MMIO, RXFF, partial);
                }         
                
            }                       
        }
        
        // TODO: Would check for other enabled interrupt types here.
             
    }                  
}

// Determines if FIFO can Rx anymore data.
int uart_can_receive(void *opaque)
{
    //printf("cpea_can_receive\n");
    CpeaMMIO *MMIO = (CpeaMMIO *)opaque;
    int rx_flag;
    int rxfifo_size;
    
    rxfifo_size = MMIO->uart->rxfifo_size; 
    
    rx_flag = MMIO->uart->queue_count < rxfifo_size;
    if (!rx_flag)
        printf("Can't RX data: Queue full\n");
             
    return rx_flag;
}

void uart_receive(void *opaque, const uint8_t *buf, int size)
{   
    CpeaMMIO *MMIO = (CpeaMMIO *)opaque;
    
    // Place Rx data into FIFO
    put_fifo(MMIO, *buf);
}

void uart_event(void *opaque, QEMUChrEvent event)
{
    if (event == CHR_EVENT_BREAK)
        printf("What the heck is this event?\n");
}

// Callback for writes to mmio region.
static void mmio_write(void *opaque, hwaddr addr,
                      uint64_t val, unsigned size)
{
    unsigned char chr;              // Character to write
    int match;                      // Flag set if register type found
	int DR_i;                       // Data Register Index
	int CR_i;                       // Control Register Index
	int SR_i;                       // Status Register Index
	
    hwaddr reg_addr = 0x40000000 + addr;   
    CpeaMMIO *MMIO = NULL;
    match = 0;

    MMIO = findMod(reg_addr, &MMIO);
    if (MMIO == NULL)
        return;
            
    // TESTING
    //chr = val;
    //if (reg_addr != 0x4006a007)
    //    qemu_chr_fe_printf(&MMIO->chrbe, "Addr: 0x%lx\nSize: %u\nVal: 0x%lx\n\n", reg_addr, size, val);
    
    DR_i = 0;
    CR_i = 0;
    SR_i = 0;
    // Determine register type accessed (DR, CR, DR). Handle accordingly. 
    while (!match){
        match = 0;
                   
        // Search DRs
        if (MMIO->DR_ADDR[DR_i] && DR_i != MAX_DR){
               
            // DR Write
            if (reg_addr ==  MMIO->DR_ADDR[DR_i]){
                
                // Determine peripheral type accessed            
                switch (MMIO->periphID){                
                case uartID:
                    chr = val;
                    /* XXX this blocks entire thread. Rewrite to use
                     * qemu_chr_fe_write and background I/O callbacks */
                    qemu_chr_fe_write_all(&MMIO->chrbe, &chr, 1);
                    break;
                    
                // Peripheral not modelled
                default:
                    break;
                } 
                match = 1;                   
            }
            DR_i++;
        }      
          
        // Search CRs
        else if (MMIO->CR_ADDR[CR_i] && CR_i != MAX_CR){
            
            // CR Write
            if (reg_addr ==  MMIO->CR_ADDR[CR_i]){               
                MMIO->CR[CR_i] = (uint32_t)val;                
                
                // Determine peripheral type accessed
                switch (MMIO->periphID){
                case uartID:
                
                    // Interrupt emulation is enabled 
                    if (MMIO->interrupt){                    
                        // RXFIFO interrupt emulation enabled
                        if (CHECK_BIT(MMIO->interrupt->enabled, RXFF)){                        
                            // Fully emulating RXFIFO Interrupt 
                            if (!CHECK_BIT(MMIO->interrupt->partial, RXFF)){
                                if (reg_addr == MMIO->interrupt->Trigger_addr[RXFF])
                                    MMIO->interrupt->Trigger_val[RXFF] = (uint32_t)val;         
                            }      
                        }        
                    }
                    break;
                
                // Peripheral not modelled
                default:
                    break;                    
                }
                
                /*
                // XXX: Testing
                qemu_chr_fe_printf(&MMIO->chrbe, 
                            "CR%d Write: 0x%x\nSize: %u, Val: 0x%lx\n\n", 
                            CR_i, MMIO->CR_ADDR[CR_i], size, val);
                */           
                            
                match = 1;
            }        
            CR_i++;
        }
    
        // Search SRs: Can likely get rid of this. SRs shouldn't be written to.
        else if (MMIO->SR_ADDR[SR_i] && SR_i != MAX_SR){
        
            // SR Write
            if (reg_addr ==  MMIO->SR_ADDR[SR_i]){               
                MMIO->SR[SR_i] = (uint32_t)val;
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
    CpeaMachineState *cms;          // CPEA Machine State
    ARMv7MState *armv7m;            // Holds CPU state
    uint32_t data;                  // Data read from FW
    uint64_t r;                     // Return value for register reads
    uint32_t PC;                    // program counter
	int SR_bit;                     // SR bit location to write to (0-31)
	int SR_val;                     // Hold SR bit value (1 or 0)
	int index;                      // Index for SR instances             
    int match;                      // Flag set if register type found
	int DR_i;                       // Data Register Index
	int CR_i;                       // Control Register Index
	int SR_i;                       // Status Register Index
    int rxfifo_size;            
 
    cms = (CpeaMachineState *)opaque;
    armv7m = cms->armv7m;

    hwaddr reg_addr = 0x40000000 + addr;
    
    CpeaMMIO *MMIO = NULL;
    match = 0;
    
    // Determine if we are accessing a peripheral we mapped.  
    MMIO = findMod(reg_addr, &MMIO);
    if (MMIO == NULL)
        return 0;

    DR_i = 0;
    CR_i = 0;
    SR_i = 0;
    // Determine register type accessed (DR, CR, DR). Handle accordingly. 
    while (!match){
        match = 0;
                   
        // Search DRs
        if (MMIO->DR_ADDR[DR_i] && DR_i != MAX_DR){
               
            // DR Read
            if (reg_addr ==  MMIO->DR_ADDR[DR_i]){
                
                // Determine peripheral type accessed            
                switch (MMIO->periphID){                
                case uartID:
                    rxfifo_size = MMIO->uart->rxfifo_size;
                    data = MMIO->uart->rx_fifo[MMIO->uart->tail];
                    if (MMIO->uart->queue_count > 0) {
                        MMIO->uart->queue_count--;
                        if (++MMIO->uart->tail == rxfifo_size)
                            MMIO->uart->tail = 0;
                    }
                    
                    // Interrupt emulation is enabled
                    if (MMIO->interrupt){
                    
                        // RXFIFO interrupt is emulated
                        if (CHECK_BIT(MMIO->interrupt->enabled, RXFF)){
                            if (MMIO->uart->queue_count < MMIO->interrupt->Trigger_val[RXFF]){             
                                // Fully emulating RXFIFO Interrupt 
                                if (!CHECK_BIT(MMIO->interrupt->partial, RXFF)){
                                
                                    // Clear RXFF SR bit                                
                                    MMIO->SR[MMIO->interrupt->SR_i[RXFF]] &= ~MMIO->interrupt->SR_set[RXFF];
                                    uart_update(MMIO, RXFF, full);
                    
                                }                                
                                // Partially emulating RXFIFO Interrupt
                                else{
                                    CLEAR_BIT(MMIO->interrupt->level, RXFF);
                                    // Clear RXFF SR bit, even if it's not emulated                                
                                    MMIO->SR[MMIO->interrupt->SR_i[RXFF]] &= ~MMIO->interrupt->SR_set[RXFF];
                                    uart_update(MMIO, RXFF, partial);
                                }               
                            }
                        }                                    
                    }
                    
                    /* TODO: Might wanna figure out exactly what this does.
                             It notifies that frontend is ready to Rx data, but
                             not sure what that exactly entails.
                    */
                        
                    // Check if Chardev exists
                    if (qemu_chr_fe_backend_connected(&MMIO->chrbe))
                        qemu_chr_fe_accept_input(&MMIO->chrbe);
                            
                    r = data;                    
                    break;
                    
                // Peripheral not modelled
                default:
                    r = 0;
                    break;
                } 
                match = 1;                   
            }
            DR_i++;
        }      
          
        // Search CRs
        else if (MMIO->CR_ADDR[CR_i] && CR_i != MAX_CR){
            
            // CR Read
            if (reg_addr ==  MMIO->CR_ADDR[CR_i]){
                r = MMIO->CR[CR_i];                                          
                match = 1;
            }        
            CR_i++;
        }
    
        // Search SRs
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
    
    int n;
    int i;
    
    if (IRQtotal){     
        // Allocate space for output 'qemu_irq's
        s->irq = g_new(qemu_irq, IRQtotal);
        
        // Allocate list to store multiple IRQn
        s->IRQn_list = (int *)malloc(sizeof(int) * IRQtotal);       
    }
    
    // Init output IRQs 
    i=0;
    for (n = 0; n < IRQtotal; n++) {
        
        // Create output IRQ line that can raise an interrupt
        qdev_init_gpio_out(DEVICE(s), &s->irq[n], 1);
        
        // Maintain a list of all IRQn   
        while (i < mmio_total){
    	    if (!MMIO[i]){
    		    printf("Error accessing MMIO%d", i);	
    		    exit(1);
    	    } 
    	 	// TODO: Will need to check if a peripheral has MULTIPLE IRQs enabled
    	    if (MMIO[i]->irq_enabled){
    	        
    	        s->IRQn_list[n] = MMIO[i]->irqn;
    	        i++;  	
    	        break;   
    	    }
    	    i++;        		
        }                
    }
}


static void cpea_init(MachineState *machine)
{
    CpeaMachineState *cms = CPEA_MACHINE(machine);
    DeviceState *cpu_dev;                            
    DeviceState *irq_driver;
    
    MemoryRegion *flash = g_new(MemoryRegion, 1);
    MemoryRegion *sram = g_new(MemoryRegion, 1);
    MemoryRegion *mmio = g_new(MemoryRegion, 1);
    MemoryRegion *system_memory = get_system_memory();
    
    // Used to init char front end
    Error *err;
    
    char arm_cpu_model[30];
    int n;
    int i;
    
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
    cms->armv7m = ARMV7M(cpu_dev);
    
    // init irq device
    irq_driver = qdev_new(TYPE_CPEA_IRQ_DRIVER); 
    cms->irq_state = CPEA_IRQ_DRIVER(irq_driver);
        
    //armv7m = ARMV7M(cpu_dev); 
    
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
    memory_region_init_io(mmio, NULL, &mmio_ops, cms, "mmio", 
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
    
    // Connect output IRQ lines to CPU's IRQn lines
    i=0;
    for (n = 0; n < IRQtotal; n++){               
        qdev_connect_gpio_out(DEVICE(irq_driver), 
                              n, 
                              qdev_get_gpio_in(cpu_dev, cms->irq_state->IRQn_list[n]));
                              
        // Save output IRQs to their respective peripheral in the same order
        // the IRQn list was created in cpea_irq_driver_init()
        while (i < mmio_total){
        
    	    if (!MMIO[i]){
    		    printf("Error accessing MMIO%d", i);	
    		    exit(1);
    	    } 
    	            
            if (MMIO[i]->irq_enabled){
                MMIO[i]->irq = cms->irq_state->irq[n];
                i++;  	
    	        break;  
            }
            
            // No IRQ enabled, move on
            else
                i++;            
        }                        
    }
    
    // Peripheral model configurations XXX: Need to findout if any of this could be apart of a device... Especially peripheral model stuff.
    /*
        1) Need to setup serial chardevs and assign them to Charbackend of peripheral
           NOTE: This would likely happen in emuConfig when automated
        2) Set up the front end handlers TODO: Just get callbacks to be issued. Can learn them later.  
           NOTE: This would also likely happen in emuConfig when automated.
    */
    
    
    // 1) Set up serial Chardevs 
    // XXX: Note limit is 4
    Chardev *chrdev[4];
    for (n=0; n<4; n++){
        chrdev[n] = serial_hd(n);
    }

    // 1) Search mmio for uart and assign a serial Chardev to UART's Charbackend
    
    i=0;
    while (i < mmio_total){
        if (!MMIO[i]){
    	    printf("Error accessing MMIO%d", i);	
    	    exit(1);
    	} 
    	
    	// If UART, assign the 2nd serial Chardev to it. 	
    	if (MMIO[i]->periphID == uartID){
    	    	
    	    // 1) Assign host's serial chardev to guest's backend
            if (!qemu_chr_fe_init(&MMIO[i]->chrbe, chrdev[0], &err)){
                printf("Failed to init Serial Chardev\n");
                exit(1);
            } 
                
            // 2) Set handlers for front-end 
            qemu_chr_fe_set_handlers(&MMIO[i]->chrbe, uart_can_receive, uart_receive,
                                    uart_event, NULL, MMIO[i], NULL, true);   	                                    
    	    break;   
    	}
    	i++;      		
    }                  
    
    
    armv7m_load_kernel(ARM_CPU(first_cpu), machine->kernel_filename,
                       cms->flash_size);
                                       
}


/* 
    Search for the accessed peripheral module
    
    Returns NULL if none found. 

*/
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
