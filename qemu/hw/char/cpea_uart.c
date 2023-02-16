#include "hw/char/cpea_uart.h"

void uart_update(CpeaMMIO *MMIO, int type, int mode)
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
     
    uint32_t CRen;
    uint32_t CRdis; 
     
    // Interrupt level used in partial emulation 
    int level; 
    
    // Indices for enable/disable CRs
    CRen = MMIO->INTR[type]->CRen;
    CRdis = MMIO->INTR[type]->CRdis;
    
    enable_permit = MMIO->INTR[type]->enable_permit;
    disable_permit = MMIO->INTR[type]->disable_permit;
    level_permit = MMIO->INTR[type]->flag_permit;

    enable_flags = MMIO->CR[CRen];
    disable_flags = MMIO->CR[CRdis];
   
    // 2 registers used for enable/disable
    if (disable_permit){
        if (enable_permit & enable_flags)
            intr_enabled |= MMIO->CR[CRen];
        else if (disable_permit & disable_flags)
            intr_enabled &= ~MMIO->CR[CRdis];    
        else
            intr_enabled = 0;                                      
    }
    
    // 1 register used for enable/disable
    else
        intr_enabled = MMIO->CR[CRen];
                    
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


int uart_can_receive(void *opaque)
{
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
    if (event == CHR_EVENT_BREAK){
        ;
    }    
}

void put_rxfifo(void *opaque, uint8_t value)
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

void fifoTx(void *opaque)
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

void fifoTimerInit(CpeaMMIO *MMIO)
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

void put_txfifo(CpeaMMIO *MMIO, uint8_t value)
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

void UARTDR_write(CpeaMMIO *MMIO, uint64_t val)
{
    unsigned char chr = (unsigned char)val;
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
}

void UARTCR_write(CpeaMMIO *MMIO, hwaddr addr, uint64_t val)
{
    int TxEmpty;                    // # of empty slots in Tx FIFO
    
    if (MMIO->INTR[RX]){
        if (MMIO->INTR[RX]->disable_permit){
            if (addr == MMIO->INTR[RX]->disable_addr)
                MMIO->CR[MMIO->INTR[RX]->CRen] &= ~(uint32_t)val;
            else if (addr == MMIO->INTR[RX]->enable_addr)
                MMIO->CR[MMIO->INTR[RX]->CRdis] &= ~(uint32_t)val;       
        }
        else{      
            if (addr == MMIO->INTR[RX]->clear_addr)
                MMIO->SR[MMIO->INTR[RX]->SRflg] &= ~(uint32_t)val;                    
            else if (addr == MMIO->INTR[RX]->trigger_addr)
                MMIO->INTR[RX]->trigger_val = (uint32_t)val;
        }               
    }
                    
    if (MMIO->INTR[TX]){
        if (MMIO->INTR[TX]->disable_permit){
            if (addr == MMIO->INTR[TX]->disable_addr)
                MMIO->CR[MMIO->INTR[TX]->CRen] &= ~(uint32_t)val;

            else if (addr == MMIO->INTR[TX]->enable_addr){
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
            if (addr == MMIO->INTR[TX]->clear_addr)
                MMIO->SR[MMIO->INTR[TX]->SRflg] &= ~(uint32_t)val;

            else if (addr == MMIO->INTR[TX]->enable_addr){
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
            else if (addr == MMIO->INTR[TX]->trigger_addr){
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
}

void UARTSR_write(CpeaMMIO *MMIO, uint64_t val)
{
    ;   // Currently no emulation required   
}


uint64_t UARTDR_read(CpeaMMIO *MMIO){

    int rxfifo_size;
    uint32_t data;
    
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
            else{
                MMIO->INTR[RX]->level = 0;                              
                MMIO->SR[MMIO->INTR[RX]->SRflg] &= ~MMIO->INTR[RX]->flag_permit;
                uart_update(MMIO, RX, partial);
            }               
        }
    }                                    
 
    if (qemu_chr_fe_backend_connected(&MMIO->chrbe))
        qemu_chr_fe_accept_input(&MMIO->chrbe);
                            
    return data;   
}





