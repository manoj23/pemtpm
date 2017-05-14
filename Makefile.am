AUTOMAKE_OPTIONS = subdir-objects

bin_PROGRAMS = pemtpm

pemtpm_CPPFLAGS = $(DEPS_CFLAGS) -DTPM_POSIX -DTPM_TSS -I$(top_srcdir)/tss/
pemtpm_LDADD = $(DEPS_LIBS)

pemtpm_SOURCES = src/importpem.c \
		 src/tssfile.c \
		 src/tssmarshal.c \
		 src/tssutils.c
