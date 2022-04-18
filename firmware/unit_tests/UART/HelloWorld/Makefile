# This Project Name should be modified per unit test
PROJECT = HelloWorld

# Select every pertinent .c file in src directories
SRCS = $(wildcard src/*.c) \
       $(wildcard ../../common/src/*.c) \
       $(wildcard ../../lib/src/*.c)
       
OBJ = obj/

# All obj files have same name as src files, AND go into OBJ directory
OBJS = $(addprefix $(OBJ), $(notdir $(SRCS:.c=.o)))

# Include directories
INC = -Iinc
LIB_INC = -I../../lib/inc
COMM_INC = -I../../common/inc

LD_SCRIPT = ../../ld/cpea.ld

GCC = arm-none-eabi-gcc
LD = arm-none-eabi-ld
OBJCOPY = arm-none-eabi-objcopy
RM      = rm -rf
# Create folders if not present
MKDIR = @mkdir -p $(@D)

# Don't link
CFLAGS = --specs=nosys.specs -ggdb -mthumb -mcpu=cortex-m4 -MD -std=c99 -c

LDFLAGS = -T $(LD_SCRIPT) -e Reset_Handler

all: bin/$(PROJECT).bin

# Compile Unit Test's source files
$(OBJ)%.o: src/%.c   
	$(MKDIR)    
	$(GCC) -o $@ $^ $(INC) $(LIB_INC) $(CFLAGS)

# Compile library source files
$(OBJ)%.o: ../../lib/src/%.c   
	$(MKDIR)    
	$(GCC) -o $@ $^ $(LIB_INC) $(CFLAGS)

# Compile all common source files 
$(OBJ)%.o: ../../common/src/%.c  
	$(MKDIR)    
	$(GCC) -o $@ $^ $(COMM_INC) $(CFLAGS)  
        
# Build elf (W/ debug symbols) by linking object files     
bin/$(PROJECT).elf: $(OBJS) 
	$(MKDIR)           
	$(LD) -o $@ $^ $(LDFLAGS)
        
# Build binary executable, stripping debug symbols     
bin/$(PROJECT).bin: bin/$(PROJECT).elf 
	$(OBJCOPY) -O binary $< $@   

clean:              
	-$(RM) obj      
	-$(RM) bin

# Don't actually build targets to right of colon for these        
.PHONY: all clean        
        
        
                
        
