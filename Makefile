CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -std=c11 -Iinclude
LDFLAGS = -lm
SRC     = src/aes.c src/trace_gen.c src/main.c
OBJ     = $(SRC:.c=.o)
TARGET  = trace-gen

.PHONY: all clean run
all: $(TARGET)
$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
run: all
	./$(TARGET)
clean:
	rm -f $(OBJ) $(TARGET) traces.bin plaintexts.csv *.png
