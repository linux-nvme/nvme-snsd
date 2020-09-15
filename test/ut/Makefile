CFLAGS := -O2 -g -Wall -Werror -D_GNU_SOURCE -fprofile-arcs -ftest-coverage
CFLAGS += -fstack-protector-strong
#CFLAGS += -fPIE -pie
CFLAGS += -Wl,-z,relro
CFLAGS += -Wl,-z,now
CFLAGS += -Wl,-z,noexecstack

CC = gcc
CPP = g++
LINK = g++

RM = rm -f
UT_TEST = snsd_ut
SRC_PATH = ../../src

default: $(UT_TEST)

LIBS += -lpthread -lgtest -lmockcpp
CFLAGS += -I$(SRC_PATH)

OBJS := $(SRC_PATH)/snsd_cfg.o		\
		$(SRC_PATH)/snsd_log.o		\
		$(SRC_PATH)/snsd_mgt.o		\
		$(SRC_PATH)/snsd_reg.o		\
		$(SRC_PATH)/snsd_switch.o   \
		$(SRC_PATH)/snsd_server.o	\
		$(SRC_PATH)/snsd_nvme.o		\
		$(SRC_PATH)/snsd_direct.o	\
		$(SRC_PATH)/snsd_connect.o	\
		$(SRC_PATH)/snsd_conn_peon.o \
		$(SRC_PATH)/snsd_conn_nvme.o 

UT_OBJS := snsd_ut.o \
			snsd_connect_ut.o	\
			snsd_cfg_ut.o	\
			snsd_mgt_ut.o \
			snsd_server_ut.o \
			snsd_switch_ut.o \
			snsd_direct_ut.o

$(UT_TEST): $(OBJS) $(UT_OBJS)
		$(LINK) $(OBJS) $(UT_OBJS) $(LIBS) $(CFLAGS) -o $(UT_TEST)

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

%.o: %.cpp
	$(CPP) $(CFLAGS) -o $@ -c $<

clean:
	$(RM) $(OBJS) $(UT_OBJS) $(UT_TEST) 
	$(RM) $(SRC_PATH)/*.gcno $(SRC_PATH)/*.gcda ./*.gcno ./*.gcda
	$(RM) $(SRC_PATH)/../test/ut/*.gcda
	$(RM) $(SRC_PATH)/../test/ut/*.gcno
