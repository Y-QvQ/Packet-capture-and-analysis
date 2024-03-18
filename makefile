CC = gcc
CFLAGS = -Wall

SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = .

# Source files for each component
BOTTOM_SRC = $(wildcard bottom/*.c)
MIDDLE_SRC = $(wildcard middle/*.c)
UPPER_SRC = $(wildcard upper/*.c)
INTERFACE_INFO_SRC = $(wildcard bottom/interfaceInfo/*.c)
IPDUMP_SRC = ipdump.c

# Object files for each component
BOTTOM_OBJ = $(patsubst bottom/%.c, $(OBJ_DIR)/bottom/%.o, $(BOTTOM_SRC))
MIDDLE_OBJ = $(patsubst middle/%.c, $(OBJ_DIR)/middle/%.o, $(MIDDLE_SRC))
UPPER_OBJ = $(patsubst upper/%.c, $(OBJ_DIR)/upper/%.o, $(UPPER_SRC))
INTERFACE_INFO_OBJ = $(patsubst bottom/interfaceInfo/%.c, $(OBJ_DIR)/bottom/interfaceInfo/%.o, $(INTERFACE_INFO_SRC))
IPDUMP_OBJ = $(OBJ_DIR)/ipdump.o

# Executables
IPDUMP = $(BIN_DIR)/ipdump

# Compilation
$(IPDUMP): $(BOTTOM_OBJ) $(MIDDLE_OBJ) $(UPPER_OBJ) $(INTERFACE_INFO_OBJ) $(IPDUMP_OBJ)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^

$(OBJ_DIR)/bottom/%.o: bottom/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ_DIR)/middle/%.o: middle/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ_DIR)/upper/%.o: upper/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ_DIR)/bottom/interfaceInfo/%.o: bottom/interfaceInfo/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ_DIR)/ipdump.o: $(IPDUMP_SRC)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

# Clean target
.PHONY: clean
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)
