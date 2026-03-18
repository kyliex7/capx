CC = gcc
CFLAGS = -Wall -Wextra
LIBS = -lpcap
SOURCES = src/capture.c src/parse_args.c src/utils.c
OBJECTS = $(SOURCES:.c=.o)
TARGET = bin/capture

$(TARGET): $(OBJECTS)
	$(CC) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)
