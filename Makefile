CFLAGS := -O2 -g -Wall -Werror -std=gnu99 -D_GNU_SOURCE
CFLAGS += -fstack-protector-strong
CFLAGS += -fPIE -pie
CFLAGS += -Wl,-z,relro
CFLAGS += -Wl,-z,now
CFLAGS += -Wl,-z,noexecstack

RM = rm -f
SNSD = nvme-snsd
LLDP_TEST = snsd_lldp_test
NT_TEST = snsd_nt_test

default: $(SNSD)

SNSD_VERSION=$(shell sh SNSD-VERSION-GEN)
CFLAGS += -DSNSD_VERSION='"$(SNSD_VERSION)"'

LIBS += -lpthread
CFLAGS += -I./src
OBJS := src/snsd_main.o		\
		src/snsd_cfg.o		\
		src/snsd_log.o		\
		src/snsd_mgt.o		\
		src/snsd_reg.o		\
		src/snsd_switch.o   \
		src/snsd_server.o	\
		src/snsd_nvme.o		\
		src/snsd_direct.o	\
		src/snsd_connect.o	\
		src/snsd_conn_peon.o \
		src/snsd_conn_nvme.o

LLDP_OBJS := src/snsd_reg.o		\
		src/snsd_log.o		\
		test/snsd_lldp_test/snsd_lldp_test.o
		
NT_OBJS := test/snsd_nt_test/snsd_nt_test.o
		
$(SNSD): $(OBJS) 
		$(CC) $(CFLAGS) $(OBJS) $(LIBS) -o $(SNSD)

$(LLDP_TEST): $(LLDP_OBJS) 
		$(CC) $(CFLAGS) $(LLDP_OBJS) -o $(LLDP_TEST)

$(NT_TEST): $(NT_OBJS) 
		$(CC) $(CFLAGS) $(NT_OBJS)  $(LIBS) -o $(NT_TEST)

%.o: %.c %.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ -c $<
		
clean:
	$(RM) $(OBJS) $(LLDP_OBJS) $(NT_OBJS) $(SNSD) $(LLDP_TEST) $(NT_TEST)
