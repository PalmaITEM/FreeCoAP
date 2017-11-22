ifeq ($(ip6),y)
EXTRA_CFLAGS = -DCOAP_IP6
endif

EXTRA_CFLAGS += -DBLOCK_SIZE=64

ifneq ($(dtls),n)
DTLS_CFLAGS = -DCOAP_DTLS_EN
DTLS_LIBS = -lgmp \
            -lhogweed \
            -lnettle \
            -lgnutls
endif

I1 = ../../lib/include
S1 = ../../lib/src

CC = gcc
CFLAGS = -Wall \
         -I $(I1) \
         -DCOAP_CLIENT_AUTH
CFLAGS += $(EXTRA_CFLAGS)
CFLAGS += $(DTLS_CFLAGS)
LD = gcc
LDFLAGS =
INCS = $(I1)/coap_server.h \
       $(I1)/coap_msg.h \
       $(I1)/coap_log.h \
       $(I1)/coap_ipv.h \
       $(I1)/http_to_mem.h
OBJS = mr_server.o \
       coap_server.o \
       coap_msg.o \
       coap_log.o \
       http_to_mem.o
LIBS = -l curl \
       $(DTLS_LIBS)
PROG = mr_server
RM = /bin/rm -f

$(PROG): $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -o $(PROG) $(LIBS)

mr_server.o: mr_server.c $(INCS)
	$(CC) $(CFLAGS) -c mr_server.c

coap_server.o: $(S1)/coap_server.c $(INCS)
	$(CC) $(CFLAGS) -c $(S1)/coap_server.c

coap_server_dtls.o: $(S1)/coap_server_dtls.c $(INCS)
	$(CC) $(CFLAGS) -c $(S1)/coap_server_dtls.c

coap_msg.o: $(S1)/coap_msg.c $(INCS)
	$(CC) $(CFLAGS) -c $(S1)/coap_msg.c

coap_log.o: $(S1)/coap_log.c $(INCS)
	$(CC) $(CFLAGS) -c $(S1)/coap_log.c

http_to_mem.o: $(S1)/http_to_mem.c $(INCS)
	$(CC) $(CFLAGS) -c $(S1)/http_to_mem.c

clean:
	$(RM) $(PROG) $(OBJS)
