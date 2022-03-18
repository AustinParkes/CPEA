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
    uint32_t enable_permit;
    uint32_t disable_permit;
    uint32_t level_permit;
    
    // Interrupt State       
    uint32_t intr_enabled = 0;
    uint32_t intr_level;   
    
    // Flags, only used if a disable register in use
    uint32_t enable_flags;
    uint32_t disable_flags;
     
    // Interrupt level used in partial emulation 
    int level; 
    
    enable_permit = MMIO->INTR[type]->enable_permit;
    disable_permit = MMIO->INTR[type]->disable_permit;
    level_permit = MMIO->INTR[type]->flag_permit;

    enable_flags = MMIO->CR[MMIO->INTR[type]->CRen];
    disable_flags = MMIO->CR[MMIO->INTR[type]->CRdis];
   
    // Disable register permitted
    if (disable_permit){
        if (enable_permit & enable_flags)
            intr_enabled |= MMIO->CR[MMIO->INTR[type]->CRen];
        else if (disable_permit & disable_flags)
            intr_enabled &= ~MMIO->CR[MMIO->INTR[type]->CRdis];    
        else
            intr_enabled = 0;                                      
    }
    else
        intr_enabled = MMIO->CR[MMIO->INTR[type]->CRen];
                    
    intr_level = MMIO->SR[MMIO->INTR[type]->SRflg];
    
    level = MMIO->INTR[type]->level;  
          
    switch (type){    
    case RX:
        switch (mode){
        case full: 
            if (enable_permit & intr_enabled && level_permit & intr_level)            
                qemu_set_irq(MMIO->INTR[type]->irq, 1);                  

            else            
                qemu_set_irq(MMIO->INTR[type]->irq, 0);
 
  

            break;        
        
        case partial:            
            if (level == 1)
                qemu_set_irq(MMIO->INTR[type]->irq, 1);    
                  
            else
                qemu_set_irq(MMIO->INTR[type]->irq, 0); 
                   
            break;
            
        // XXX: This is technically an error    
        default:
            break;    
        }                                    
        break;
    
    case TX:
        switch (mode){
        case full:
            if (enable_permit & intr_enabled && level_permit & intr_level){
                MMIO->INTR[type]->active = 1;          
                qemu_set_irq(MMIO->INTR[type]->irq, 1);                  
            }
            else{ 
                MMIO->INTR[type]->active = 0;       
                qemu_set_irq(MMIO->INTR[type]->irq, 0);
            }    
                            
            break;
            
        case partial:
            break;
            
        // XXX: This is technically an error    
        default:
            break;        
                
        }
        break;
                        
    default:
        break;        
    }       
}

static void put_rxfifo(void *opaque, uint8_t value)
{

    CpeaMMIO *MMIO = (CpeaMMIO *)opaque;
    int slot;
    int rxfifo_size;

    rxfifo_size = MMIO->uart->rxfifo_size;
    
    // Slot is where we place data. read is where we read data.
    slot = MMIO->uart->read + MMIO->uart->rxqueue_cnt;
    
    if (slot >= rxfifo_size)
        slot -= rxfifo_size;
   
    MMIO->uart->rx_fifo[slot] = value;
    MMIO->uart->rxqueue_cnt++;          
         
    if (MMIO->INTR[RX]){            
        if (MMIO->uart->rxqueue_cnt >= MMIO->INTR[RX]->trigger_val){           
            if (MMIO->INTR[RX]->mode == full){               
                MMIO->SR[MMIO->INTR[RX]->SRflg] |= MMIO->INTR[RX]->flag_permit;
                uart_update(MMIO, RX, full);
                    
            }                                
            else{
                MMIO->INTR[RX]->level = 1;
                // SR can still be partially emulated in partial mode
                MMIO->SR[MMIO->INTR[RX]->SRflg] |= MMIO->INTR[RX]->flag_permit;
                uart_update(MMIO, RX, partial);
            }         
                
        }                       
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
    
    rx_flag = MMIO->uart->rxqueue_cnt < rxfifo_size;

    if (!rx_flag)
        printf("Can't RX data: Queue full\n");
             
    return rx_flag;
}

void uart_receive(void *opaque, const uint8_t *buf, int size)
{   
    CpeaMMIO *MMIO = (CpeaMMIO *)opaque;
    
    // Place Rx data into FIFO
    put_rxfifo(MMIO, *buf);
}

void uart_event(void *opaque, QEMUChrEvent event)
{
    if (event == CHR_EVENT_BREAK)
        printf("What the heck is this event?\n");
}

static void fifoTx(void *opaque)
{

    CpeaMMIO *MMIO = (CpeaMMIO *)opaque;
    QEMUTimer *fifo_timer = MMIO->uart->fifo_timer;
    fifo_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL, fifoTx, MMIO);
        
    int TxEmpty;            // Number of empty slots in Tx FIFO     
    uint8_t chr;
    
    int txfifo_size = MMIO->uart->txfifo_size;
    
    // Deplete FIFO (Tx data)
    if (MMIO->uart->txqueue_cnt > 0){
        chr = MMIO->uart->tx_fifo[MMIO->uart->write];
        qemu_chr_fe_write(&MMIO->chrbe, &chr, 1);        
        
        MMIO->uart->txqueue_cnt--;
        
        // Update Tx FIFO count if the register is emulated
        if (MMIO->uart->txf_cnt_addr)
            MMIO->SR[MMIO->uart->SRtxf_cnt] = MMIO->uart->txqueue_cnt;
        
        // Update FIFO Full flag if the register is emulated
        if (MMIO->uart->txff_permit){
        
            // Flag cleared when FIFO not full
            if (MMIO->uart->txff_polarity != 0){
                MMIO->SR[MMIO->uart->SRtxff] &= ~MMIO->uart->txff_permit;    
            }
            
            // Flag set when FIFO not full
            else{                
                MMIO->SR[MMIO->uart->SRtxff] |= MMIO->uart->txff_permit;
            }
        }
                
        if (++MMIO->uart->write == txfifo_size)
            MMIO->uart->write = 0;

        // TODO: Update timer the same way it was initialized 
        int64_t now = qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL);
        int64_t duration = 100;
        timer_mod(fifo_timer, now + duration);  
        
        TxEmpty = MMIO->uart->txfifo_size - MMIO->uart->txqueue_cnt; 
        if (TxEmpty >= MMIO->INTR[TX]->trigger_val){
            MMIO->SR[MMIO->INTR[TX]->SRflg] |= MMIO->INTR[TX]->flag_permit;
            uart_update(MMIO, TX, full);
        }                                   
    }
    
                           
}

static void fifoTimerInit(CpeaMMIO *MMIO)
{

    QEMUTimer *fifo_timer = MMIO->uart->fifo_timer;
    fifo_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL, fifoTx, MMIO);
    
    int64_t now = qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL);
    
    // Duration should be roughly equivalent to 1200 bytes/s (9600 baud)   
    // (~ 0.83 ms per byte)
    // TODO: Too fast?
    int64_t duration = 100;
    
    // Modify timer to expire at duration and issue fifoTx callback
    timer_mod(fifo_timer, now + duration);
    
    MMIO->uart->TimerActive = 1;
}

static void put_txfifo(CpeaMMIO *MMIO, uint8_t value)
{
    
    int slot;
    int txfifo_size;
    
    txfifo_size = MMIO->uart->txfifo_size;
    
    slot = MMIO->uart->write + MMIO->uart->txqueue_cnt;
    
    if (slot >= txfifo_size)
        slot -= txfifo_size;   
           
    MMIO->uart->tx_fifo[slot] = value;
    MMIO->uart->txqueue_cnt++;
    
    // Update Tx FIFO count if the register is emulated
    if (MMIO->uart->txf_cnt_addr)
        MMIO->SR[MMIO->uart->SRtxf_cnt] = MMIO->uart->txqueue_cnt;

    // Set timer and activate Tx fifo transmission
    if (!MMIO->uart->TimerActive)
        fifoTimerInit(MMIO);   

    // XXX: May re-consider if we want to manually clear interrupt. This SHOULD be FWs job. 
    if (MMIO->uart->txqueue_cnt == txfifo_size){
        
        // Update FIFO Full flag if the register is emulated
        if (MMIO->uart->txff_permit){
            // Flag set when FIFO full
            if (MMIO->uart->txff_polarity != 0){
                MMIO->SR[MMIO->uart->SRtxff] |= MMIO->uart->txff_permit;
            }
            
            // Flag cleared when FIFO full
            else{
                MMIO->SR[MMIO->uart->SRtxff] &= ~MMIO->uart->txff_permit;
            }
        }
        
        MMIO->SR[MMIO->INTR[TX]->SRflg] &= ~MMIO->INTR[TX]->flag_permit;
        uart_update(MMIO, TX, full); 
    }      
       
}

// Callback for writes to mmio region.
static void mmio_write(void *opaque, hwaddr addr,
                      uint64_t val, unsigned size)
{
    unsigned char chr;              // Character to write
    int match;                      // Flag set if register type found
	int DR_i = 0;                   // Data Register Index
	int CR_i = 0;                   // Control Register Index
	int SR_i = 0;                   // Status Register Index
	int TxEmpty;                    // # of empty slots in Tx FIFO
	
    hwaddr reg_addr = 0x40000000 + addr;   
    CpeaMMIO *MMIO = NULL;
    match = 0;

    MMIO = findMod(reg_addr, &MMIO);
    if (MMIO == NULL)
        return;

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
  
                    // Tx Interrupt active
                    if (MMIO->INTR[TX]){
                        if (MMIO->INTR[TX]->active){
                            if (MMIO->INTR[TX]->trigger_val != 0){                                
                                put_txfifo(MMIO, chr);            
                            }
                            /*
                            TODO: This is Non-FIFO Tx interrupt
                                  Ignore it for now, test later
                            else
                                qemu_chr_fe_write_all(&MMIO->chrbe, &chr, 1);
                            */    
                                                                          
                        }

                        else
                            qemu_chr_fe_write_all(&MMIO->chrbe, &chr, 1);
                            
                    }
                    else
                        qemu_chr_fe_write_all(&MMIO->chrbe, &chr, 1);   

                    /*
                    TODO: This is Non-FIFO Tx interrupt
                          Ignore it for now, test later
                    if (MMIO->INTR[TX]){
                        if (MMIO->INTR[TX]->mode == full){
                            MMIO->SR[MMIO->INTR[TX]->SRflg] |= MMIO->INTR[TX]->flag_permit;
                            uart_update(MMIO, TX, full);       
                        }
                        else{
                            MMIO->INTR[TX]->level = 1;
                            MMIO->SR[MMIO->INTR[TX]->SRflg] |= MMIO->INTR[TX]->flag_permit;
                            uart_update(MMIO, TX, partial);                         
                        }
                    }
                    */
                    
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
                   
                    // TODO: Turn these Rx Intr CR checks into a function                
                    if (MMIO->INTR[RX]){
                        if (MMIO->INTR[RX]->disable_permit){
                            if (reg_addr == MMIO->INTR[RX]->disable_addr)
                                MMIO->CR[MMIO->INTR[RX]->CRen] &= ~(uint32_t)val;
                            else if (reg_addr == MMIO->INTR[RX]->enable_addr)
                                MMIO->CR[MMIO->INTR[RX]->CRdis] &= ~(uint32_t)val;       
                        }
                        else{      
                            if (reg_addr == MMIO->INTR[RX]->clear_addr)
                                MMIO->SR[MMIO->INTR[RX]->SRflg] &= ~(uint32_t)val;
                    
                            else if (reg_addr == MMIO->INTR[RX]->trigger_addr)
                                MMIO->INTR[RX]->trigger_val = (uint32_t)val;
                        }               
                    }
                    
                    // TODO: Turn these Tx Intr CR checks into a function
                    if (MMIO->INTR[TX]){
                        if (MMIO->INTR[TX]->disable_permit){
                            if (reg_addr == MMIO->INTR[TX]->disable_addr)
                                MMIO->CR[MMIO->INTR[TX]->CRen] &= ~(uint32_t)val;

                            else if (reg_addr == MMIO->INTR[TX]->enable_addr){
                                MMIO->CR[MMIO->INTR[TX]->CRdis] &= ~(uint32_t)val;
                                // TODO: Check if trigger configured and reached, if so set flag and update
                                //       If not continue
                                //       CHECK IF WORKS
                                if (MMIO->INTR[TX]->trigger_val != 0){
                                    TxEmpty = MMIO->uart->txfifo_size - MMIO->uart->txqueue_cnt;
                                    if (TxEmpty >= MMIO->INTR[TX]->trigger_val){
                                        MMIO->SR[MMIO->INTR[TX]->SRflg] |= MMIO->INTR[TX]->flag_permit;
                                        uart_update(MMIO, TX, full);
                                    }    
                                }   
                            }           
                        }   
                        else{                    
                            if (reg_addr == MMIO->INTR[TX]->clear_addr)
                                MMIO->SR[MMIO->INTR[TX]->SRflg] &= ~(uint32_t)val;

                            else if (reg_addr == MMIO->INTR[TX]->enable_addr){
                                // TODO: Check if trigger configured and reached, if so set flag and update
                                //       If not continue 
                                //       CHECK IF WORKS
                                if (MMIO->INTR[TX]->trigger_val != 0){
                                    TxEmpty = MMIO->uart->txfifo_size - MMIO->uart->txqueue_cnt;
                                    if (TxEmpty >= MMIO->INTR[TX]->trigger_val){
                                        MMIO->SR[MMIO->INTR[TX]->SRflg] |= MMIO->INTR[TX]->flag_permit;
                                        uart_update(MMIO, TX, full);
                                    }    
                                }                                                                                               
   
                            }
                            else if (reg_addr == MMIO->INTR[TX]->trigger_addr){
                                MMIO->INTR[TX]->trigger_val = (uint32_t)val;
                                // TODO: Check if trigger value surpassed, if so set flag and update
                                //       If not continue. update will check if intr enabled
                                //       CHECK IF WORKS                                
                                if (MMIO->INTR[TX]->trigger_val != 0){
                                    TxEmpty = MMIO->uart->txfifo_size - MMIO->uart->txqueue_cnt;
                                    if (TxEmpty >= MMIO->INTR[TX]->trigger_val){
                                        MMIO->SR[MMIO->INTR[TX]->SRflg] |= MMIO->INTR[TX]->flag_permit;
                                        uart_update(MMIO, TX, full);
                                    }    
                                }                                   
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
                    data = MMIO->uart->rx_fifo[MMIO->uart->read];
                    if (MMIO->uart->rxqueue_cnt > 0) {
                        MMIO->uart->rxqueue_cnt--;
                        if (++MMIO->uart->read == rxfifo_size)
                            MMIO->uart->read = 0;
                    }                    
                    // RX interrupt is emulated
                    if (MMIO->INTR[RX]){
                        if (MMIO->uart->rxqueue_cnt < MMIO->INTR[RX]->trigger_val){             
                            if (MMIO->INTR[RX]->mode == full){                                                          
                                MMIO->SR[MMIO->INTR[RX]->SRflg] &= ~MMIO->INTR[RX]->flag_permit;
                                uart_update(MMIO, RX, full);
                    
                            }                                
                            // Partially emulating RX Interrupt
                            else{
                                MMIO->INTR[RX]->level = 0;                              
                                MMIO->SR[MMIO->INTR[RX]->SRflg] &= ~MMIO->INTR[RX]->flag_permit;
                                uart_update(MMIO, RX, partial);
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
    cms->armv7m = ARMV7M(cpu_dev);
    
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
