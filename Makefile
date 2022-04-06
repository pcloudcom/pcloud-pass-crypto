CC=cc
AR=ar rc
RANLIB=ranlib
USESSL=mbedtls

#CFLAGS=-Wall -Wpointer-arith -g -O2 -fsanitize=address
#CFLAGS=-Wall -Wpointer-arith -g -O2 -fPIC
CFLAGS=-Wall -Wpointer-arith -g -O2

LIB_A=libppass.a

OBJ=ppass.o

CFLAGS += -I../mbedtls-3.1.0/include

all: $(LIB_A)

$(LIB_A): $(OBJ)
	$(AR) $@ $(OBJ)
	$(RANLIB) $@

clean:
	rm -f *~ *.o $(LIB_A)

