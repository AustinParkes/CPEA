/*
 * MachineState for CPEA. Contains all configurable variables needed for Cortex-M
 * TODO: Extend description
 * Written by Austin Parkes.
*/

#ifndef HW_ARM_CPEA_H_
#define HW_ARM_CPEA_H_

#include <stdint.h>
#include "cpea/toml.h"
#include "hw/boards.h"
#include "hw/sysbus.h"
#include "hw/arm/armv7m.h"
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
    
    ARMv7MState *armv7m;
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

// Interrupt types 
enum uartIntr_type {
    RXFF,
    TXFF
};
                
enum intr_mode {
    full, 
    partial
};

typedef struct interrupt {

    int enabled;
    int mode;   
    int level;
    
    // CR that enables the interrupt type
    uint32_t CR_enable;
    uint32_t CR_i;
    
    // SR that is set upon a condition to generate the interrupt type
    uint32_t SR_set;
    uint32_t SR_i;
    
    // IRQ specifics
    int irq_enabled;
	int irqn;
	qemu_irq irq;
    
    // # of bytes in a FIFO that trigger interrupt   
    uint32_t Trigger_val;
    uint32_t Trigger_addr;  
     
} interrupt;

typedef struct uart{

	uint8_t *rx_fifo;       // RX FIFO, size is configurable
	int rxfifo_size;        
	int tail;               // Slot data is read from
	int queue_count;        // Number of datawords in rx_fifo    

    // Peripheral Interaction. Guest's "backend"
	CharBackend chrbe;

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
 * RXFFParse: Parse RX FIFO Full / RX Data Register Full interrupts
 *
 * Returns 0-Error, 1-Success
 */
int RXFFParse(toml_table_t* TablePtr, toml_table_t* AddrTab, 
              int intrType, int struct_i);


/**
 * CheckIntrData: Checks the data type entered by user (string / integer)
 *                GetIntrData will usually be called sometime after this.
 *
 * Returns 0-Error, 1-String, 2-Integer
 *
 */
int CheckIntrData(toml_table_t* InlineTable, const char *InlineTableName, 
                  const char *InlineTableKey, int dataRep);

/**
 * GetIntrData: Retrieves data from an inline table 
 *              CheckIntrData is typically called before this.
 *              CheckIntrReg may be called after this.
 *
 * Returns a union containing a register string or integer value
 *
 */
toml_datum_t GetIntrData(toml_table_t* InlineTable, const char *InlineTableName,  
                const char *InlineTableKey, int dataType, int dataRep);

/**
 * checkPartial: Checks if a control register is entered for emulation                
 *               Partial emulation if no CR is entered
 *               Full emulation if a CR is entered
 *               This should be used when parsing SRs since they need to be
 *               configured in full emulation scenarios.
 *                  
 * Returns 0-Full Emulation 1-Partial Emulation
 *
 */
int checkPartial(const char *InlineTableName, const char *InlineTableKey,
                 int intrType, int struct_i);


/**
 * CheckIntrReg: Checks the input given to a register field. 
 *               Makes sure user entered a valid register or checks if 
 *               user is doing partial emulation. This should only be
 *               used to check register fields.
 *
 *               Partial emulation should only be set for enable fields
 *
 * Returns 0-Invalid Reg 1-Valid Reg 2-Partial Emulation 3-Nothing entered
 */
int CheckIntrReg(toml_datum_t IntrData, toml_table_t* AddrTab, 
              const char *InlineTableName, const char *InlineTableKey,
              int intrType, int struct_i);

/**
 * getRegAddr: Gets the address of a register. We need addresses
 *             of some registers to emulate them when they are accessed.
 *             GetIntrData is usually called before this.
 *
 * Returns an address
 *
 */
int getRegAddr(toml_datum_t IntrData, toml_table_t* AddrTab);


/**
 * getRegReset: Gets the reset value of a register. We need the reset
 *              value to give a register its inital value to emulate it.
 *
 * Returns a reset value
 *
 */
int getRegReset(toml_datum_t IntrData, toml_table_t* AddrTab);

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
 * findMod: Find peripheral module accessed in callback.
 *
 */	
CpeaMMIO *findMod(uint64_t, CpeaMMIO**);

/**
 * uart_can_receive: 
 *
 */
int uart_can_receive(void *opaque);

/**
 * uart_receive: 
 *
 */
void uart_receive(void *opaque, const uint8_t *buf, int size);

/**
 * uart_event:
 *
 */
void uart_event(void *opaque, QEMUChrEvent event);

/**
 * intr_alloc: Allocate an interrupt struct for each enabled interrupt
 *             in a peripheral
 *
 * Returns 0-Error 1-Success
 */
int intr_alloc(toml_table_t* TablePtr, int struct_i);

/**
 * error: 
 *
 */
void error(const char *, const char *, const char *, const char *); 

#endif /* CPEA_H_ */
