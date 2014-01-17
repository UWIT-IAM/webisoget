lib_LTLIBRARIES = libwebisoget.la
libwebisoget_la_SOURCES = webisogetlib.c

include_HEADERS=webisoget.h

bin_PROGRAMS=webisoget

man1_MANS = doc/webisoget.man

EXTRA_DIST=COPYRIGHT README CHANGES doc/webisoget.man doc/webisoget.html webisoget.spec

LDADD=-lwebisoget -lcurl -lssl -lcrypto -lz

