#ifndef emulatorConfig_H_
#define emulatorConfig_H_

#include <stdint.h>
#include "cpea/toml.h"
#include "hw/arm/cpea.h"

void error(const char *, const char *, const char *, const char *);           
toml_table_t *parseConfig(toml_table_t *, CpeaMachineState **);	
CpeaMachineState *emuConfig(CpeaMachineState *);
int mmioConfig(toml_table_t *);				            
int setFlags(toml_table_t *, int);					   
void parseKeys(char *, const char *, toml_table_t *, const char *, int);
void cp_mem_write(uint64_t, const void *, size_t);
void cp_mem_read(uint64_t, void *, size_t);

/*
void intr_setup();              // Automatic stacking and other setups for interrupt handlers
// Callback Declarations 
int pre_read_MMIO();    // Before an MMIO register is read
int post_read_MMIO();   // After an MMIO register is read
void write_MMIO();      // After an MMIO register is written to
void enter_intr();      // Callback to enter exception handlers  
void exit_intr();       // Callback for leaving exception handlers
void write_SCS();       // Monitor writes to System Control Space
void fire_intr();       // Fires interrupt every 1,000 basic blocks (bbls)
*/

// Max array sizes

#define MAX_INST 1000           // TODO: Find better max number for saved SR instances?

// Set kth bit in a register
#define SET_BIT(reg, k)     (reg |= (1<<k))	
#define CLEAR_BIT(reg, k)   (reg &= ~(1<<k))

// Check kth bit in a register
#define CHECK_BIT(reg, k)   (reg & (1<<k))

/* Interrupts */
/*
extern int INTR_EN;            // Interrupt firing enabled/disabled for emulator
extern int INTR_PTR;           // Points to next interrupt to fire
extern int n_cnt;              // Points to ISERn to fire interrupts
extern int m_cnt;              // Points to a bit in ISERn to fire interrupts
*/


/*******************/
/*** MMIO Config ***/
/*******************/
extern int mmio_total;             // Total number of peripherals 
extern int SR_count;               // Number of SR for a module
extern int DR_count;               // Number of DR for a module

// min/max register addresses for any given peripheral module. (Helps locate modules in findMod())
extern uint32_t minPeriphaddr;
extern uint32_t maxPeriphaddr;


// Peripherals and their corresponding ID to determine which structures belong to which periph.
enum periphID {uartID, gpioID, genericID};

// To index correct SR or DR
enum Status_Register {SR1, SR2, SR3, SR4, SR5, SR6, SR7, SR8};
enum Data_Register {DR1, DR2};		


// Saves SR instances for particular SR accesses.
extern int inst_i;
typedef struct SR_INSTANCE{

    uint32_t INST_ADDR;                   // Program address SR is accessed at.
    int BIT;                              // SR Bit location   
    int VAL;                              // SR Bit 0/1             //unsigned int VAL :1; TODO: Could make this binary.
    
} INST_handle;
extern INST_handle *SR_INSTANCE[MAX_INST];

#endif /* emulatorConfig_H_ */
