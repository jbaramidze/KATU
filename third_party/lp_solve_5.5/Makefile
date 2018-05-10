
CC = gcc # C compiler
CFLAGS = -fPIC -Wall -Wextra -O2 -g -Ishared -Icolamd -Ibfp -Ibfp/bfp_LUSOL -I. -Ibfp/bfp_LUSOL/LUSOL -DLoadableBlasLib=0 -DYY_NEVER_INTERACTIVE -DPARSER_LP -DINVERSE_ACTIVE=INVERSE_LUSOL -DRoleIsExternalInvEngine -DLoadInverseLib=0 -DLoadLanguageLib=0
LDFLAGS = -shared # linking flags
LDLIBS = -lm -lc
RM = rm -f  # rm command
TARGET_LIB = liblpsolver.so # target lib

SRCS=$(wildcard *.c)
SSRCS=$(wildcard shared/*.c)
CSRCS=$(wildcard colamd/*.c)
BSRCS=$(wildcard bfp/bfp_LUSOL/*.c)
BBSRCS=$(wildcard bfp/bfp_LUSOL/LUSOL/*.c)




OBJS=$(SRCS:.c=.o)
SOBJS=$(SSRCS:.c=.o)
COBJS=$(CSRCS:.c=.o)
BOBJS=$(BSRCS:.c=.o)
BBOBJS=$(BBSRCS:.c=.o)


.PHONY: all
all: ${TARGET_LIB}

$(TARGET_LIB): $(OBJS) $(SOBJS) $(COBJS) $(BOBJS) $(BBOBJS)
	$(CC) ${LDFLAGS} -o $@ $^ ${LDLIBS}

$(SRCS:.c=.d):%.d:%.c
	$(CC) $(CFLAGS) -MM $< >$@

.PHONY: clean
clean:
	-${RM} ${TARGET_LIB} ${OBJS} $(SOBJS) $(COBJS) $(BOBJS) $(BBOBJS) $(SRCS:.c=.d)
