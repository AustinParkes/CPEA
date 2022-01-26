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
    ability to trigger interrupts.I also believe this is the CPU's clocking freq.
*/
#define SYSCLK_FRQ 120000000ULL

static void put_fifo(void *opaque, uint8_t value)
{

    CpeaMMIO *MMIO = (CpeaMMIO *)opaque;
    int tail;
    
    // Tail is where we place data. Head is where we read data.
    tail = MMIO->head + MMIO->queue_count;
    
    //tail = tail % 16;
    if (tail >= 16)
        tail -= 16;

    printf("tail: %d\n", tail);    
    MMIO->rx_fifo[tail] = value;
    MMIO->queue_count++;
      
                      
}

// Determines if FIFO can Rx anymore data.
static int cpea_can_receive(void *opaque)
{
    printf("Check if we can Rx data\n");
    CpeaMMIO *MMIO = (CpeaMMIO *)opaque;
    int rx_flag;
    /* TODO: Need to discern if we are in FIFO mode or not, then see if our 
             queue length is too long to Rx anymore data in FIFO.
             If too long, queue length will naturally decrease when data is read from FIFO.
             Also, can't increase more if we don't Rx more data.
    */
    
    rx_flag = MMIO->queue_count < 16;
    if (!rx_flag)
        printf("Can't RX data: Queue full\n");
        
    return rx_flag;
}
static void cpea_receive(void *opaque, const uint8_t *buf, int size)
{   
    printf("Woohoo!!!\n");
    CpeaMMIO *MMIO = (CpeaMMIO *)opaque;
    
    // Place Rx data into FIFO
    put_fifo(MMIO, *buf);
}
static void cpea_event(void *opaque, QEMUChrEvent event)
{
    if (event == CHR_EVENT_BREAK)
        printf("What the heck is this event?\n");
}

// Callback for writes to mmio region
// TODO: Log data that is written to registers.
static void mmio_write(void *opaque, hwaddr addr,
                      uint64_t val, unsigned size)
{
    return;
}   

static uint64_t mmio_read(void *opaque, hwaddr addr,
                      unsigned size)
{
    CpeaMachineState *cms;          // CPEA Machine State
    ARMv7MState *armv7m;            // Holds CPU state
    uint32_t PC;                    // program counter
	int SR_bit;                     // SR bit location to write to (0-31)
	int SR_val;                     // Hold SR bit value (1 or 0)
	int addr_i;                     // Index registers' addresses
	int index;                      // Index for SR instances
 
    cms = (CpeaMachineState *)opaque;
    armv7m = cms->armv7m;

    // Compute absolute addr from offset
    hwaddr reg_addr = 0x40000000 + addr;
    
    CpeaMMIO *periphx = NULL;	// Points to the peripheral mmio accessed. 
    
    // Determine if we are accessing a peripheral we mapped.  
    periphx = findMod(reg_addr, &periphx);
    if (periphx == NULL)
        return -1;
        
    // Find register being accessed and handle according to type (DR, CR or SR)
    for (addr_i=0; addr_i < MAX_SR; addr_i++){
    
        // DR accessed
        if (addr_i < 2){
            if (reg_addr == periphx->DR_ADDR[addr_i]){
                
                return 0;
            } 
        }
        
        // SR accessed
        if (reg_addr == periphx->SR_ADDR[addr_i]){
            
            // SR instance doesn't exist.
            if (!periphx->SR_INST){
                return periphx->SR[addr_i];
            }
    
            // SR instance exists
	        else {	
	            /* 
	                This environment (env) contains the LAST executed address and the results from that.
	                So, R15 is not up to date with the current PC, but R0-R14 are up to date.
	                
	                We need the current PC. One way to remedy is to check if we are within a byte of the desired PC.
	                NOTE: PC is a instruction ahead when stepping through in GDB (e.g. would be 0x19f2 instead of 0x19f0 at that point)
	                TODO  Need to take this into account for someone using GDB       
	            */
	            
	            PC = armv7m->cpu->env.regs[15];     // Get program counter

                /* 
                    XXX: Pulse the UART IRQ Handler in the FW to test that IRQ firing works.
                         Works Fine when pulsing. :) Runs the handler once then leaves.  
                           
	            if (PC == 0x19f0 || PC == 0x19f2){
	                printf("PC: 0x19f2\n");

	                // Locate IRQn 31 and set it's associatated qemu_irq
	                for (int n=0; n < IRQtotal; n++){
	                    printf("n: %d and IRQn: %d\n", n, cms->irq_state->IRQn_list[n]);
	                    if (cms->irq_state->IRQn_list[n] == 31){
	                        printf("Set IRQ!\n");
	                        
	                        // Pulse IRQ. If set and never unset, stays in handler forever. 
	                        qemu_irq_pulse(cms->irq_state->irq[n]);
	                        
	                        // NOTE: These are equivalent to pulsing
	                        //qemu_set_irq(cms->irq_state->irq[n], 1);
	                        //qemu_set_irq(cms->irq_state->irq[n], 0);  
	                    }    
	                }                    	
	            }
	            */ 
	  
	            // Loop SR instances & look for match
	            for (index = 0; index < inst_i; index++){
	                
	                // HACK: We only have access to the previous PC. Check if SR instance is within a byte of PC. 
	                if (SR_INSTANCE[index]->INST_ADDR >= PC && SR_INSTANCE[index]->INST_ADDR <= PC + 4){ 
	                    SR_bit = SR_INSTANCE[index]->BIT;
	                    SR_val = SR_INSTANCE[index]->VAL;
	                    if (SR_val == 1)
	                        SET_BIT(periphx->SR[addr_i], SR_bit);
	                    else
	                        CLEAR_BIT(periphx->SR[addr_i], SR_bit);
	                    
	                    return periphx->SR[addr_i]; 
	                } 
	            }
	            
	            // No instance at accessed address, so return register value.
	            return periphx->SR[addr_i];   
            }      
        }
    }

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
    CpeaIRQDriverState *s = CPEA_IRQ_DRIVER(obj);
    
    int n;
    int mod_i;
    
    if (IRQtotal){     
        // Allocate space for output 'qemu_irq's
        s->irq = g_new(qemu_irq, IRQtotal);
        
        // Allocate list to store multiple IRQn
        s->IRQn_list = (int *)malloc(sizeof(int) * IRQtotal);       
    }
    
    // Init output IRQs 
    mod_i=0;
    for (n = 0; n < IRQtotal; n++) {
        
        // Create output IRQ line that can raise an interrupt
        qdev_init_gpio_out(DEVICE(s), &s->irq[n], 1);
        
        // Assign IRQs to peripherals to set IRQs easily later  
        while (mod_i < mmio_total){
    	    if (!MMIO[mod_i]){
    		    printf("Error accessing MMIO%d", mod_i);	
    		    exit(1);
    	    } 
    	 	
    	    if (MMIO[mod_i]->irq_enabled){
    	        MMIO[mod_i]->irq = &s->irq[n];
    	        
    	        // Also, maintain a list of all IRQn 
    	        s->IRQn_list[n] = MMIO[mod_i]->irqn;
    	        mod_i++;  	
    	        break;   
    	    }
    	    mod_i++;        		
        }                
    }
        
    printf("IRQ Driver Device Init!\n");
}

static void mmio_trigger(void *opaque, int irq, int level){

    printf("Trigger: %d\n", irq);    
    
}

static void cpea_mmio_init(Object *obj)
{    
    /*
    DeviceState *dev = DEVICE(obj);
    CpeaMMIOState *s = CPEA_MMIO(obj);
    SysBusDevice *sbd = SYS_BUS_DEVICE(obj);
    
    int n;  
    
    if (IRQtotal) 
        s->irq = g_new(qemu_irq, IRQtotal);
   
    // Init output IRQs.
    for (n = 0; n < IRQtotal; n++) {
        sysbus_init_irq(sbd, &s->irq[n]);
    }
    
    // Each IRQ should have its own input 'qemu_irq'
    if (IRQtotal)
        qdev_init_gpio_in(dev, mmio_trigger, IRQtotal);
    
    
    
    //sysbus_init_irq(sbd, &s->irqn);
    
    qdev_init_gpio_in(dev, mmio_trigger, 1);
                           
    printf("MMIO Device Init!\n");
    */
}

static void cpea_init(MachineState *machine)
{
    CpeaMachineState *cms = CPEA_MACHINE(machine);
    //CpeaIRQDriverState *irq_state;
    //ARMv7MState *armv7m;
    DeviceState *cpu_dev;                            
    DeviceState *irq_driver;
    
    MemoryRegion *flash = g_new(MemoryRegion, 1);
    MemoryRegion *sram = g_new(MemoryRegion, 1);
    MemoryRegion *mmio = g_new(MemoryRegion, 1);
    MemoryRegion *system_memory = get_system_memory();
    
    // Currently being used to init char front end
    Error *err;
    
    char arm_cpu_model[30];
    int n;
    
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
    for (n = 0; n < IRQtotal; n++){               
        qdev_connect_gpio_out(DEVICE(irq_driver), 
                              n, 
                              qdev_get_gpio_in(cpu_dev, cms->irq_state->IRQn_list[n]));  
    }
    
    // Peripheral model configurations XXX: Need to findout if any of this could be apart of a device... Especially peripheral model stuff.
    /*
        1) Need to setup serial chardevs and assign them to Charbackend of peripheral
           NOTE: This would likely happen in emuConfig when automated
        2) Set up the front end handlers TODO: Just get callbacks to be issued. Can learn them later.  
           NOTE: This would also likely happen in emuConfig when automated.
    */
    
    // 1) Set up serial Chardevs
    Chardev *chrdev[4];
    for (n=0; n<4; n++){
        chrdev[n] = serial_hd(n);
        if (serial_hd(n))
            printf("serial %d\n", n);
    }

    // 1) Search mmio for uart and assign a serial Chardev to UART's Charbackend
    
    int mod_i=0;
    while (mod_i < mmio_total){
        if (!MMIO[mod_i]){
    	    printf("Error accessing MMIO%d", mod_i);	
    	    exit(1);
    	} 
    	
    	// If UART, assign the 2nd serial Chardev to it. 	
    	if (MMIO[mod_i]->periphID == uartID){
    	    	
    	    // 1) Assign host's serial chardev to guest's backend
            if (!qemu_chr_fe_init(&MMIO[mod_i]->chrbe, chrdev[0], &err)){
                printf("Failed to init Serial Chardev\n");
                exit(1);
            } 

            // XXX: This didn't work for some reason. Using the function above instead.
            //MMIO[0]->chrbe.chr = chrdev[0];
                
            // 2) Set handlers for front-end 
            qemu_chr_fe_set_handlers(&MMIO[mod_i]->chrbe, cpea_can_receive, cpea_receive,
                                    cpea_event, NULL, MMIO[mod_i], NULL, true);   	                                    
    	    break;   
    	}
    	mod_i++;      		
    }        
    
	// XXX: This does write to the monitor backend ONLY when backend/frontend is specified on command line
    unsigned char ch[] = "Hello World\n";
    qemu_chr_fe_write_all(&MMIO[0]->chrbe, ch, 13);

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
