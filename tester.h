void show_config();			// Show emulator and peripheral configurations.
void show_structures();		// Show peripheral data structures to see if they match configurations.
void read_fbin();			// Show opcode or data of a binary file to cross check it against Ghidra.
void show_regs();			// Show variable registers at any point in time.
void show_mmio();			// Show various memory contents of certain mmio
void show_UART();			// Goes inside show_mmio() to show UART mmio contents.

