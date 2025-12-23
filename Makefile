CC = gcc
CFLAGS = -Wall -Wextra -O2 -pthread -std=gnu99
TARGET = netscope
SRCDIR = src
INCDIR = include
OBJDIR = obj

# Source files
SRCS = $(SRCDIR)/main.c $(SRCDIR)/args.c $(SRCDIR)/banner.c $(SRCDIR)/output.c $(SRCDIR)/scanner.c $(SRCDIR)/signal.c $(SRCDIR)/utils.c

# Object files
OBJS = $(OBJDIR)/main.o $(OBJDIR)/args.o $(OBJDIR)/banner.o $(OBJDIR)/output.o $(OBJDIR)/scanner.o $(OBJDIR)/signal.o $(OBJDIR)/utils.o

# Include directories
INCLUDES = -I$(INCDIR)

# Create obj directory if it doesn't exist
$(OBJDIR):
	mkdir -p $(OBJDIR)

# Compile object files
$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Link the executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET)

# Clean build artifacts
clean:
	rm -rf $(OBJDIR) $(TARGET)

# Install the binary (optional)
install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

# Uninstall the binary (optional)
uninstall:
	rm -f /usr/local/bin/$(TARGET)

# Phony targets
.PHONY: clean install uninstall

# Default target
all: $(TARGET)
