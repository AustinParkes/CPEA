#ifndef CPEA_CALLBACKS_H_
#define CPEA_CALLBACKS_H_

#include <stdint.h>
#include <stddef.h>
//#include "hw/arm/cpea.h"
#include "cpea/peripherals.h"

struct IOfuncs {
    void        (*DRwrite)(CpeaMMIO *MMIO, uint64_t val);
    void        (*CRwrite)(CpeaMMIO *MMIO, hwaddr addr, uint64_t val);
    void        (*SRwrite)(CpeaMMIO *MMIO, uint64_t val);
    uint64_t    (*DRread)(CpeaMMIO *MMIO);    
    uint64_t    (*CRread)(CpeaMMIO *MMIO);  /* TODO: No current emulation of this. Prototype is being guessed. */   
    uint64_t    (*SRread)(CpeaMMIO *MMIO);  /* TODO: No current emulation of this. Prototype is being guessed. */     
};  
extern const struct IOfuncs emulateIO[];

#endif  /* CPEA_CALLBACKS_H_ */
