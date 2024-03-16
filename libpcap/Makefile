CC = gcc
CFLAGS = -Wall -Wextra
LIBS = -lpcap

SRCS:=$(wildcard *.c)
OBJS:=$(SRCS:%.c=%.o)

TARGET = libpcap_program

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) $(LIBS) -o $(TARGET)

clean:
	$(RM) $(TARGET) $(OBJS)
