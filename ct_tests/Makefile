CC=gcc
CFLAGS=-Wall
SOURCES=$(wildcard *.c)
BINARIES=$(SOURCES:.c=)
DEPS=$(SOURCES:.c=.d) # Dependency files

# Default target
all: $(BINARIES)

# Include the dependency files
-include $(DEPS)

# Rule to compile each .c to a binary and generate a .d file
%: %.c
	$(CC) $(CFLAGS) -MMD -MP -o $@ $<

# Clean up binaries and dependency files
clean:
	rm -f $(BINARIES) $(DEPS)

