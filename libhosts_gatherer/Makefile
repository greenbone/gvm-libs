include ../nessus.tmpl
COMPILE = $(CC) $(DEFS) $(include) $(CFLAGS)
LTCOMPILE = $(LIBTOOL) --mode=compile $(CC) $(DEFS) $(include) $(CFLAGS)
LINK = $(LIBTOOL) --mode=link $(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(WS2_32)


OBJS = hg_utils.o hg_add_hosts.o hg_subnet.o hg_filter.o hosts_gatherer.o \
	hg_debug.o hg_dns_axfr.o

LO_OBJS = hg_utils.lo hg_add_hosts.lo hg_subnet.lo hg_filter.lo \
	hosts_gatherer.lo hg_debug.lo hg_dns_axfr.lo


all : libhosts_gatherer.la

test : libhosts_gatherer.la 
	$(COMPILE)  test.c -o test -L.libs -lhosts_gatherer $(LIBS)

install : libhosts_gatherer.la
	test -d $(DESTDIR)${libdir} || $(INSTALL_DIR) -m 755 $(DESTDIR)${libdir}
	$(LIBTOOL) --mode install $(INSTALL) libhosts_gatherer.la $(DESTDIR)${libdir} 
	$(LIBTOOL) --finish $(DESTDIR)${libdir}
	
libhosts_gatherer.la : $(OBJS)
	$(LIBTOOL) $(CC) -o libhosts_gatherer.la $(LO_OBJS) -rpath ${libdir} \
	-version-info ${PACKAGE_VERSION}
	        
hg_utils.o : hg_utils.h hosts_gatherer.h hg_utils.c
	$(LIBTOOL) --mode=compile  $(COMPILE) -c hg_utils.c

hg_add_hosts.o : hg_add_hosts.h hosts_gatherer.h hg_add_hosts.c
	$(LIBTOOL) --mode=compile  $(COMPILE) -c hg_add_hosts.c

hg_subnet.o : hg_subnet.h hosts_gatherer.h hg_subnet.c
	$(LIBTOOL) --mode=compile  $(COMPILE) -c hg_subnet.c
	
hg_filter.o : hg_filter.h hosts_gatherer.h hg_filter.c
	$(LIBTOOL) --mode=compile  $(COMPILE) -c hg_filter.c	

hosts_gatherer.o : hosts_gatherer.h hosts_gatherer.c
	$(LIBTOOL) --mode=compile  $(COMPILE) -c hosts_gatherer.c
		
hg_dns_axfr.o : hg_dns_axfr.c hosts_gatherer.h hg_dns_axfr.c
	$(LIBTOOL) --mode=compile $(COMPILE) -c hg_dns_axfr.c
	
hg_debug.o : hg_debug.c hosts_gatherer.h hg_debug.c
	$(LIBTOOL) --mode=compile  $(COMPILE) -c hg_debug.c
	
distclean : clean
	
clean :
	@rm -f OBJ/* lib*.a *~ *core *.lo *.o lib*.la
	@rm -rf .libs
