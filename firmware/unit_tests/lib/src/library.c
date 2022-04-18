#include <stdio.h>
#include "library.h"

void enable_irqs(void){

    uint32_t const *NVIC_ISER_START = (uint32_t *)0xE000E100;
    uint32_t const *NVIC_ISER_END = (uint32_t *)0xE000E11C;
    
    uint32_t *NVIC_PTR = (uint32_t *)NVIC_ISER_START;
    
    while (NVIC_PTR <= NVIC_ISER_END){
        *NVIC_PTR = (uint32_t)0xFFFFFFFF;
        NVIC_PTR += (uint32_t)4;
    }        
}

void cp_wait(int t){
    
    for (int i = 0; i < t*10000; i++){
        ;   // Do nothing except wait
    }   
    
}

void cp_memset(char *src, int c, int size){

    int i;    
    for (i = 0; i < size; i++){
        *src = (unsigned char)c;
        *src++;
    }
}

int cp_strncmp(const char *str1, const char *str2, int n){

    int i;
    
    for (i = 0; i < n; i++){
        if (*str1 == *str2){
            str1++;
            str2++;
        }
                
        // Failure
        else
            return 1;
    }
    
    return 0;    
}

void print_char(uint8_t c, volatile uint8_t *DR){
    *DR = (uint32_t)c;
}

void print(const char *s, volatile uint8_t *DR){
    while (*s != '\0'){
        *DR = (uint32_t)(*s);
        s++;
    }
}

void print_cmd(char *buf, volatile uint8_t *DR){
    int c = 0;
    while (buf[c] != '\0'){
        print_char(buf[c], DR);
        c++;
    }
    print("\n", DR);
}
