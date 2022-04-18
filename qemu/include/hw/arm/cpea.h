/*
 * MachineState for CPEA. Contains all configurable variables needed for Cortex-M
 *
 * Written by Austin Parkes.
*/

#ifndef HW_ARM_CPEA_H_
#define HW_ARM_CPEA_H_

#include <stdint.h>
#include "cpea/toml.h"
#include "hw/boards.h"
#include "hw/sysbus.h"
#include "hw/irq.h"
#include "sysemu/sysemu.h"
#include "chardev/char-fe.h"
#include "chardev/char.h"


#define SET_BIT(reg, k)     (reg |= (1<<k))	
#define CLEAR_BIT(reg, k)   (reg &= ~(1<<k))
#define CHECK_BIT(reg, k)   (reg & (1<<k))

// TODO: Need to define appropriate upper bounds for these
#define MAX_MMIO 100
#define MAX_MODS 16            
#define MAX_CR 20              
#define MAX_SR 20               
#define MAX_DR 2
#define MAX_INTR 10            
#define MAX_INST 1000          

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
    
    CpeaIRQDriverState *irq_state;

};

struct CpeaIRQDriverState {
    SysBusDevice parent_obj;
       
    qemu_irq *irq;    
    int *IRQn_list;  
};

extern int IRQtotal;
extern int mmio_total;            
extern int CR_count;
extern int SR_count;
extern int DR_count;
extern uint32_t minPeriphaddr;
extern uint32_t maxPeriphaddr;
extern int inst_i;

enum regType {CR_type, SR_type, DR_type};
enum periphID {null, uartID, gpioID, genericID};
enum Status_Register {SR1, SR2, SR3, SR4, SR5, SR6, SR7, SR8};
enum Data_Register {DR1, DR2};

// Interrupt parsing
enum dType {STRING = 1, INTEGER = 2};
enum dRep {REG = 1, BIT = 2};

enum uartIntr_type {
    RX,
    TX
};
                
enum intr_mode {
    full, 
    partial
};

/* interrupt: Contains information for a peripheral's interrupt(s) 
 *
 *
 * @mode: Full (0) or Partial (1) emulation
 * @active: Interrupt currently active (1) or inactive (0) 
 *          Some interrupts need this while others don't
 * @enable_permit: Flag tables that allows a CR enable bit to be emulated
 * @enable_addr: Address of CR that enables an interrupt. Only needed if an 
                 interrupt disable register is used in tandem
 * @CRen: Index for the CR that enables interrupt in FW
 * @disable_permit: Flag tables that allow a CR disable bit to be emulated
 * @disable_addr: Address of CR that disables an interrupt. Need the address
 *                to emulate hardware in realtime (during MMIO write)
 * @CRdis: Index for the CR that disables interrupt in FW
 * @flag_permit: Flag tables that allows a SR bit to be emulated (interrupt status)
 * @SRflg: Index for the SR whose bits convey interrupt status
 * @clear_addr: Address of the interrupt clear register to emulate. It's assumed
 *              bits written to the ICR correspond to the bits to clear in the SR
 * @level: interrupt's running status during partial emulation
 *
 * @irq_enabled: IRQ enable flag
 * @irqn: The IRQ number for this interrupt
 * @irq: Output IRQ to raise interrupts
 *
 * @trigger_val: FIFO threshold value which triggers an interrupt
 * @trigger_addr: Address of CR that contains FIFO threshold value (optional)
 */
typedef struct interrupt {

    int mode;
    int active; 
       
    uint32_t enable_permit;
    uint32_t enable_addr;    
    uint32_t CRen;
    
    uint32_t disable_permit;
    uint32_t disable_addr;
    uint32_t CRdis;

    uint32_t flag_permit;
    uint32_t SRflg;
    
    uint32_t clear_addr;      
    
    int level;
    
    int irq_enabled;
	int irqn;
	qemu_irq irq;
    
    // TODO: Could probably move this into uart's peripheral model
    uint32_t trigger_val;
    uint32_t trigger_addr;    
      
     
} interrupt;


/* uart: Contains information for UART hardware 
 * @txff_permit: Allows Tx FIFO Full flag to be emulated
 * @txff_addr: Address the register the Tx FIFO Full bit belongs to 
 * @SRtxff: Index of the SR that the txff flag is stored in
 * @txff_polarity: '1' means Tx FIFO is full when the bit value is '1'
 *                 '0' means Tx FIFO is full when the bit value is '0'
 * @SRtxf_size: Index of the register that contains Tx FIFO size
 * @txf_cnt_addr: Address of the register that contains count of datawords
 *                in Tx FIFO
 * @SRtxf_cnt: Index of the SR that Tx FIFO count is stored in               
 *
 *
 *
 *
 *
 *
 *
 *
 * @TimerActive: Timer is active (1) vs non-active (0) to which it issues
 *               a callback periodically to deplete FIFO 
 *  
 */
typedef struct uart{

    /* Registers */
    uint32_t txff_permit;
    uint32_t txff_addr;     // TODO: This isn't used
    uint32_t SRtxff;
    int txff_polarity;
    
    uint32_t SRtxf_size;    
    
    uint32_t txf_cnt_addr;
    uint32_t SRtxf_cnt;
    
    /* Hardware */
	uint16_t *rx_fifo;
	int rxfifo_size;     
    int read;
    int rxqueue_cnt;

    uint16_t *tx_fifo;
	int txfifo_size; 	
	int write;
	int txqueue_cnt;
    int TimerActive;

    // Peripheral Interaction. Guest's "backend"
	CharBackend chrbe;
	
	
	
	QEMUTimer *fifo_timer;

} CpeaUART;	
		
// MMIO Structure for all peripherals. 
typedef struct MMIO{

    // Metadata
    int periphID;                           // ID of which peripheral this struct is for. e.g. uart, gpio, etc.
    int modID;                              // ID for which module this is. e.g. 0, 1, 2, etc
    int modCount;                           // Number of total modules for this peripheral
    int minAddr;                            // Lowest register address for this module 
    int maxAddr;                            // Highest register address for this module
    int mmioSize;                           // Number of addresses this peripheral takes up 

    // Registers
    uint32_t BASE_ADDR;
	
	uint32_t CR_ADDR[MAX_CR];
    uint32_t SR_ADDR[MAX_SR];                  
    uint32_t DR_ADDR[MAX_DR];					

    uint32_t CR[MAX_CR];
    uint32_t SR[MAX_SR];                        
    uint32_t DR[MAX_DR];
	
	// SR instance flag
	int SR_INST;
	
	// Interrupts 
	interrupt *INTR[MAX_INTR];

	// Peripheral Interaction
	// TODO: This will go into the individual peripheral models
	CharBackend chrbe;
	
    // Peripheral Models
    CpeaUART *uart;
	
} CpeaMMIO;
extern CpeaMMIO *MMIO[MAX_MMIO];

// Saves SR instances for particular SR accesses.
typedef struct SR_INSTANCE{

    uint32_t INST_ADDR;                   // Program address SR is accessed at.
    int BIT;                              // SR Bit location   
    int VAL;                              // SR Bit 0/1             //unsigned int VAL :1; TODO: Could make this binary.
    
} INST_handle;
extern INST_handle *SR_INSTANCE[MAX_INST];

/**
 * genericHWConfig: Hardware Configuration for generic peripherals
 *
 */
void genericHWConfig(toml_table_t* mmio, char* p_name, const char* module_str, 
                toml_table_t* table_ptr, const char* table_str, int struct_i);

/**
 * uartHWConfig: UART Hardware Configuration
 *
 */
void uartHWConfig(toml_table_t* mmio, char* p_name, const char* module_str, 
                toml_table_t* table_ptr, const char* table_str, int struct_i);

/**
 * getFifoSize: Gets FIFO size and commits to MMIO struct
 *
 * Returns 0-Error 1-Success
 */
int getFifoSize(CpeaUART uart, toml_table_t* TablePtr, int struct_i);


/**
 * genericIntrConfig: Interrupt Configuration for generic peripherals
 *
 */
void genericIntrConfig(toml_table_t* mmio, char* p_name, const char* module_str, 
                toml_table_t* table_ptr, const char* table_str, int struct_i);

/**
 * uartIntrConfig: UART Interrupt Configuration
 *
 */
void uartIntrConfig(toml_table_t* mmio, char* p_name, const char* module_str, 
                toml_table_t* table_ptr, const char* table_str, int struct_i);

/**
 * RXParse: Parse RX interrupts
 *
 * Returns 0-Error, 1-Success
 */
int RXParse(toml_table_t* TablePtr, toml_table_t* AddrTab, 
              toml_table_t* ResetTab, int intrType, int struct_i);

/**
 * TXParse: Parse TX Interrupts
 *
 * Returns 0-Error, 1-Success
 */
int TXParse(toml_table_t* TablePtr, toml_table_t* AddrTab, 
              toml_table_t* ResetTab, int intrType, int struct_i);

/**
 * getRegAddr: Gets the address of a register. We need addresses
 *             of some registers to emulate them when they are accessed.
 *             GetIntrData is usually called before this.
 *
 * Returns an address
 *
 */
int getRegAddr(toml_table_t* AddrTab, const char *IntrName,
            toml_datum_t IntrData);


/**
 * getRegReset: Gets the reset value of a register. We need the reset
 *              value to give a register its inital value to emulate it.
 *
 * Returns a reset value
 *
 */
int getRegReset(toml_table_t* ResetTab, const char *IntrName,
            toml_datum_t IntrData);

/**
 * genericInterface: Interface Configuration for generic peripherals
 *
 */
void genericInterface(toml_table_t* mmio, char* p_name, const char* module_str, 
                toml_table_t* table_ptr, const char* table_str, int struct_i);

/**
 * uartInterface: UART Interface Configuration
 *
 */
void uartInterface(toml_table_t* mmio, char* p_name, const char* module_str, 
                toml_table_t* table_ptr, const char* table_str, int struct_i);

/**
 * parseConfig: 
 *
 */          
toml_table_t *parseConfig(toml_table_t *, CpeaMachineState **);	

/**
 * emuConfig: 
 *
 */
CpeaMachineState *emuConfig(CpeaMachineState *);

/**
 * mmioConfig: 
 *
 */
int mmioConfig(toml_table_t *);	
	
	
/**
 * checkIRQ: Check if an IRQn is configured for an interrupt 
 *
 * Returns 0-No IRQ 1-IRQ Configured
 */		
int checkIRQ(const char *InlineTableName, int intrType, 
            int checkType, int struct_i);	
	
/**
 * setFlags: 
 *
 */		            
int setFlags(toml_table_t *, int);
	
/**
 * parseKeys:
 *
 */				   
void parseKeys(toml_table_t*, char *, const char *, toml_table_t *, const char *, int);

/**
 * findMod: Find peripheral module accessed in MMIO callback.
 *
 * Returns Pointer to peripheral being accessed
 *         NULL if none found
 */	
CpeaMMIO *findMod(uint64_t address, CpeaMMIO** periph);


/*
int uart_can_receive(void *opaque);
void uart_receive(void *opaque, const uint8_t *buf, int size);
void uart_event(void *opaque, QEMUChrEvent event);
*/


/**
 * intr_alloc: Allocate an interrupt struct for each enabled interrupt
 *             in a peripheral
 *
 * Returns 0-Error 1-Success
 */
int intr_alloc(toml_table_t* TablePtr, int struct_i);

/**
 * GetEmuMode: Check and obtain the interrupt mode of a particular interrupt
 *             Will determine if interrupt is fully emulated or partially
 *             emulated
 *             
 * Returns 0-Error 1-Success 2-Skip 
 */
int GetEmuMode(toml_table_t* ConfigTable, const char *IntrName, 
        int intrType, int struct_i);


/**
 * IntrEnable: Check and obtain configurations for a configuration
 *             register that enables an interrupt
 *              
 *             
 * Returns 0-Error 1-Success
 */
int IntrEnable(toml_table_t* IntrTable, const char *IntrName, 
        toml_table_t* AddrTab, int intrType, int struct_i);

/**
 * IntrDisable: Check and obtain configurations for a configuration
 *              register that disables an interrupt
 *              
 *             
 * Returns 0-Error 1-Success
 */
int IntrDisable(toml_table_t* IntrTable, const char *IntrName, 
        toml_table_t* AddrTab, int intrType, int struct_i);
        
/**
 * IntrClear: Check and obtain configurations for a configuration
 *            register that clears an interrupt's status bit
 *              
 *             
 * Returns 0-Error 1-Success
 */
int IntrClear(toml_table_t* IntrTypeTable, const char *IntrName, 
        toml_table_t* AddrTab, int intrType, int struct_i);

/**
 * IntrStatus: Check and obtain configurations for the status register
 *             that says an interrupt is ready to fire 
 *             
 * Returns 0-Error 1-Success
 */
int IntrStatus(toml_table_t* IntrTypeTable, const char *IntrName, 
        toml_table_t* AddrTab, int intrType, int struct_i);
 
 
/**
 * fifoFull:  
 *             
 *              
 *             
 * Returns 0-Error 1-Success
 */ 
int fifoFull(toml_table_t* IntrTypeTable, const char *IntrName, 
        toml_table_t* AddrTab, int intrType, int struct_i);

/**
 * fifoSize:  
 *             
 *              
 *             
 * Returns 0-Error 1-Success
 */ 
int fifoSize(toml_table_t* IntrTypeTable, const char *IntrName, 
        toml_table_t* AddrTab, int intrType, int struct_i);

/**
 * fifoCount:  
 *             
 *              
 *             
 * Returns 0-Error 1-Success
 */ 
int fifoCount(toml_table_t* IntrTypeTable, const char *IntrName, 
        toml_table_t* AddrTab, int intrType, int struct_i); 
        
/**
 * fifoTrigger: Get the FIFO threshold value in the form of a value
 *              or an actual control register which contains
 *              a threshold value  
 *             
 * Returns 0-Error 1-Success
 */
int fifoTrigger(toml_table_t* IntrTypeTable, const char *IntrName, 
        toml_table_t* AddrTab, toml_table_t* ResetTab, 
        int intrType, int struct_i);

/**
 * GetIntrData: Gets data from configuration fields
 *              Performs checks on register and bit fields
 *              to see if data is valid
 *              
 *             
 * Returns toml_datum_t: A union containing data or error code
 */
toml_datum_t GetIntrData(toml_table_t* IntrTypeTable, toml_table_t* AddrTab, 
            const char *IntrName, const char *ConfigName, const char *dataKey);
           
/**
 * error: 
 *
 */
void error(const char *, const char *, const char *, const char *); 

#endif /* CPEA_H_ */
