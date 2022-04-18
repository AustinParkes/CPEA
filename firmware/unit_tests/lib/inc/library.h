/** 
 *  enable_irqs: Enable all ISRs in NVIC. Essential if you want interrupts.
 *
*/
void enable_irqs(void);

/**
 * cp_wait: Wait for t*10,000 empty loop iterations
 *
 */
void cp_wait(int t);

/** 
 *  cp_memset: Set 'c' in 'src' for 'size' bytes
 *
*/
void cp_memset(char *src, int c, int size);

/** 
 *  cp_strncmp: Compare the first 'n' bytes of two strings
 *
 * Returns 0 - Match 1 - No match
*/
int cp_strncmp(const char *str1, const char *str2, int n);

/** 
 *  print: Print a string into a Data Register
 *
*/
void print(const char *s, volatile uint8_t *DR);

/** 
 *  print_char: Print a character into a Data Register
 *
*/
void print_char(uint8_t c, volatile uint8_t *DR);

/** 
 *  print_cmd: Prints contents of a buffer. 
 *  Assumes buffer ends with null terminator!
 *  (e.g. print the command a user entered)
 *
*/
void print_cmd(char *buf, volatile uint8_t *DR);
