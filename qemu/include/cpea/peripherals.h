/*
    Place header files for peripheral emulation here    
*/

#ifndef CPEA_PERIPHERALS_H_
#define CPEA_PERIPHERALS_H_

#include "hw/char/cpea_uart.h"

/**
 * peripheralID: Display peripheral IDs for user configuration
 *
 * @name: Name of the peripheral
 * @impl: Peripheral has emulation support (TRUE) 
 *        or does not have support (FALSE)
 * @id: Peripheral ID is displayed for a reader's clarity
 *      since the index itself could be used as the ID.
 *
 */
struct peripheralID {
    char *name;
    bool impl;
    uint16_t id;
};

extern const struct peripheralID IDTable[];

#endif  /* CPEA_PERIPHERALS_H__ */
