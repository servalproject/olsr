OLSRD_PLUGIN =  true
PLUGIN_NAME =   olsrd_relay
PLUGIN_VER =    0.1

TOPDIR =        ../..
include $(TOPDIR)/Makefile.inc

default_target: $(PLUGIN_FULLNAME)

$(PLUGIN_FULLNAME): $(OBJS) version-script.txt
	@echo "[LD] $@"
	@$(CC) $(LDFLAGS) -o $(PLUGIN_FULLNAME) $(OBJS) $(LIBS)

install:	$(PLUGIN_FULLNAME)
	$(STRIP) $(PLUGIN_FULLNAME)
	$(INSTALL_LIB)

uninstall:
	$(UNINSTALL_LIB)

clean:
	rm -f $(OBJS) $(SRCS:%.c=%.d) $(PLUGIN_FULLNAME)
