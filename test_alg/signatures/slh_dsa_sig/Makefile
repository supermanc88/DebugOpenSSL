CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99
INCLUDES = -I../../openssl-3.5.2/include
LIBS = -L../../openssl-3.5.2 -lssl -lcrypto
TARGET = slh_dsa_sig_test
SOURCE = slh_dsa_sig.c

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(TARGET) $(SOURCE) $(LIBS)

clean:
	rm -f $(TARGET)

test: $(TARGET)
	./$(TARGET)

.PHONY: all clean test