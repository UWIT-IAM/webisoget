include_HEADERS=webisoget.h

bin_PROGRAMS=webisoget
webisoget_SOURCES=webisoget.c webisogetlib.c

man1_MANS = doc/webisoget.man

EXTRA_DIST=COPYRIGHT README CHANGES doc/webisoget.man doc/webisoget.html webisoget.spec

LDADD=-lcurl -lssl -lcrypto -lz

ACLOCAL_AMFLAGS=-I m4
