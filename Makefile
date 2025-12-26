CC = gcc
CFLAGS = -Wall -Wextra -O2 -pthread -std=gnu99
TARGET = netscope
SRCDIR = src
INCDIR = include
OBJDIR = obj

# Source files
SRCS = $(SRCDIR)/main.c $(SRCDIR)/args.c $(SRCDIR)/banner.c $(SRCDIR)/output.c $(SRCDIR)/scanner.c $(SRCDIR)/signal.c $(SRCDIR)/utils.c $(SRCDIR)/service_detect.c $(SRCDIR)/syn_scan.c $(SRCDIR)/iot_scan.c

# Object files
OBJS = $(OBJDIR)/main.o $(OBJDIR)/args.o $(OBJDIR)/banner.o $(OBJDIR)/output.o $(OBJDIR)/scanner.o $(OBJDIR)/signal.o $(OBJDIR)/utils.o $(OBJDIR)/service_detect.o $(OBJDIR)/syn_scan.o $(OBJDIR)/iot_scan.o

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
	@echo "Installing $(TARGET) to /usr/local/bin/"
	@if cp $(TARGET) /usr/local/bin/ 2>/dev/null; then \
		echo "$(TARGET) installed successfully!"; \
	else \
		echo "Permission denied. Try: sudo make install"; \
	fi

# Uninstall the binary (optional)
uninstall:
	@echo "Removing $(TARGET) from /usr/local/bin/"
	@if rm -f /usr/local/bin/$(TARGET) 2>/dev/null; then \
		echo "$(TARGET) removed successfully!"; \
	else \
		echo "Permission denied. Try: sudo make uninstall"; \
	fi

# Phony targets
.PHONY: clean install uninstall

# Default target
all: $(TARGET)
