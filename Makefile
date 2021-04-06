.PHONY: all clean

CFLAGS+=-Wall
LDLIBS+=-lasound

all: alsa-monitor

clean:
	$(RM) alsa-monitor
