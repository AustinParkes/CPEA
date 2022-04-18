#ifndef HW_CPEA_UART_H_
#define HW_CPEA_UART_H_

#include <stdio.h>
#include "qemu/osdep.h"
#include "hw/arm/cpea.h"

/**
 * uart_update: Updates interrupt state based on a combination
 *              of user configured interrupts and emulated interrupt
 *              conditions.
 *              For example, if an interrupt condition is met by the emulator, 
 *              the interrupt will only fire if the user configured that 
 *              interrupt to be emulated.
 *              
 */
void uart_update(CpeaMMIO *MMIO, int type, int mode);

/**
 * uart_can_receive: Callback to determine if UART Rx FIFO can receive anymore 
 *                   data from a user.                   
 *                   If the FIFO is full, then no more data can be received
 *                   from the user.
 *                   The result of this handler determines if uart_receive() 
 *                   will be called.
 *
 * Returns True - FIFO not full and uart_receive() called 
 *         False - FIFO full and uart_receive() not called
 */
int uart_can_receive(void *opaque);

/**
 * uart_receive: Callback for Rx FIFO to receive more data from a user
 *               Makes call to put_rxfifo() to place this data.  
 *
 */
void uart_receive(void *opaque, const uint8_t *buf, int size);

/**
 * uart_event: No current use of this.
 *             Kept incase the function was filled with something useful
 *
 */ 
void uart_event(void *opaque, QEMUChrEvent event);

/**
 * put_rxfifo: Place received user data into Rx FIFO, update FIFO state,
 *             and check condition for Rx interrupt
 *
 */
void put_rxfifo(void *opaque, uint8_t value);

/**
 * fifoTx: Deplete Tx FIFO, update interrupt status, and update the
 *         timer for when the next dataword should transmit from the Tx FIFO 
 *
 */
void fifoTx(void *opaque);

/**
 * fifoTimerInit: Initialize a timer that will issue a callback
 *                every timer period to transmit a datword from the Tx FIFO
 *
 */  
void fifoTimerInit(CpeaMMIO *MMIO);

/**
 * put_txfifo: Places data written from FW into Tx FIFO, inits Tx FIFO timer,
 *             and updates interrupt state
 *
 */
void put_txfifo(CpeaMMIO *MMIO, uint8_t value);

/**
 * UARTDR_write: Handle DR writes to UART
 *
 */
void UARTDR_write(CpeaMMIO *MMIO, uint64_t val);

/**
 * UARTCR_write: Handle CR writes to UART
 * 
 * @MMIO: Peripheral being accessed
 * @addr: Full address accessed. Not an offset
 * @val: Value being written to CR
 */
void UARTCR_write(CpeaMMIO *MMIO, hwaddr addr, uint64_t val);

/**
 * UARTSR_write: Handle SR writes to UART
 *
 */

void UARTSR_write(CpeaMMIO *MMIO, uint64_t val);

/**
 * UARTDR_read: Handle DR reads from UART
 *
 */
uint64_t UARTDR_read(CpeaMMIO *MMIO);


#endif  /* HW_CHAR_CPEA_UART_H_ */
