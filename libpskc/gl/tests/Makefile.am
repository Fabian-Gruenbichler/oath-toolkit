## DO NOT EDIT! GENERATED AUTOMATICALLY!
## Process this file with automake to produce Makefile.in.
# Copyright (C) 2002-2013 Free Software Foundation, Inc.
#
# This file is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This file is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this file.  If not, see <http://www.gnu.org/licenses/>.
#
# As a special exception to the GNU General Public License,
# this file may be distributed as part of a program that
# contains a configuration script generated by Autoconf, under
# the same distribution terms as the rest of that program.
#
# Generated by gnulib-tool.

AUTOMAKE_OPTIONS = 1.5 foreign

SUBDIRS = .
TESTS =
XFAIL_TESTS =
TESTS_ENVIRONMENT =
noinst_PROGRAMS =
check_PROGRAMS =
noinst_HEADERS =
noinst_LIBRARIES =
check_LIBRARIES = libtests.a
EXTRA_DIST =
BUILT_SOURCES =
SUFFIXES =
MOSTLYCLEANFILES = core *.stackdump
MOSTLYCLEANDIRS =
CLEANFILES =
DISTCLEANFILES =
MAINTAINERCLEANFILES =

AM_CPPFLAGS = \
  -D@gltests_WITNESS@=1 \
  -I. -I$(srcdir) \
  -I../.. -I$(srcdir)/../.. \
  -I../../gl -I$(srcdir)/../../gl

LDADD = libtests.a ../../gl/libgnu.la libtests.a $(LIBTESTS_LIBDEPS)

libtests_a_SOURCES =
libtests_a_LIBADD = $(gltests_LIBOBJS)
libtests_a_DEPENDENCIES = $(gltests_LIBOBJS)
EXTRA_libtests_a_SOURCES =
AM_LIBTOOLFLAGS = --preserve-dup-deps

TESTS_ENVIRONMENT += EXEEXT='@EXEEXT@' srcdir='$(srcdir)'

## begin gnulib module alloca-opt

BUILT_SOURCES += $(ALLOCA_H)

# We need the following in order to create <alloca.h> when the system
# doesn't have one that works with the given compiler.
if GL_GENERATE_ALLOCA_H
alloca.h: alloca.in.h $(top_builddir)/config.status
	$(AM_V_GEN)rm -f $@-t $@ && \
	{ echo '/* DO NOT EDIT! GENERATED AUTOMATICALLY! */'; \
	  cat $(srcdir)/alloca.in.h; \
	} > $@-t && \
	mv -f $@-t $@
else
alloca.h: $(top_builddir)/config.status
	rm -f $@
endif
MOSTLYCLEANFILES += alloca.h alloca.h-t

EXTRA_DIST += alloca.in.h

## end   gnulib module alloca-opt

## begin gnulib module alloca-opt-tests

TESTS += test-alloca-opt
check_PROGRAMS += test-alloca-opt

EXTRA_DIST += test-alloca-opt.c

## end   gnulib module alloca-opt-tests

## begin gnulib module base64-tests

TESTS += test-base64
check_PROGRAMS += test-base64
EXTRA_DIST += test-base64.c macros.h

## end   gnulib module base64-tests

## begin gnulib module errno

BUILT_SOURCES += $(ERRNO_H)

# We need the following in order to create <errno.h> when the system
# doesn't have one that is POSIX compliant.
if GL_GENERATE_ERRNO_H
errno.h: errno.in.h $(top_builddir)/config.status
	$(AM_V_GEN)rm -f $@-t $@ && \
	{ echo '/* DO NOT EDIT! GENERATED AUTOMATICALLY! */' && \
	  sed -e 's|@''GUARD_PREFIX''@|GL|g' \
	      -e 's|@''INCLUDE_NEXT''@|$(INCLUDE_NEXT)|g' \
	      -e 's|@''PRAGMA_SYSTEM_HEADER''@|@PRAGMA_SYSTEM_HEADER@|g' \
	      -e 's|@''PRAGMA_COLUMNS''@|@PRAGMA_COLUMNS@|g' \
	      -e 's|@''NEXT_ERRNO_H''@|$(NEXT_ERRNO_H)|g' \
	      -e 's|@''EMULTIHOP_HIDDEN''@|$(EMULTIHOP_HIDDEN)|g' \
	      -e 's|@''EMULTIHOP_VALUE''@|$(EMULTIHOP_VALUE)|g' \
	      -e 's|@''ENOLINK_HIDDEN''@|$(ENOLINK_HIDDEN)|g' \
	      -e 's|@''ENOLINK_VALUE''@|$(ENOLINK_VALUE)|g' \
	      -e 's|@''EOVERFLOW_HIDDEN''@|$(EOVERFLOW_HIDDEN)|g' \
	      -e 's|@''EOVERFLOW_VALUE''@|$(EOVERFLOW_VALUE)|g' \
	      < $(srcdir)/errno.in.h; \
	} > $@-t && \
	mv $@-t $@
else
errno.h: $(top_builddir)/config.status
	rm -f $@
endif
MOSTLYCLEANFILES += errno.h errno.h-t

EXTRA_DIST += errno.in.h

## end   gnulib module errno

## begin gnulib module errno-tests

TESTS += test-errno
check_PROGRAMS += test-errno

EXTRA_DIST += test-errno.c

## end   gnulib module errno-tests

## begin gnulib module fdopen


EXTRA_DIST += fdopen.c

EXTRA_libtests_a_SOURCES += fdopen.c

## end   gnulib module fdopen

## begin gnulib module fdopen-tests

TESTS += test-fdopen
check_PROGRAMS += test-fdopen
EXTRA_DIST += test-fdopen.c signature.h macros.h

## end   gnulib module fdopen-tests

## begin gnulib module fgetc-tests

TESTS += test-fgetc
check_PROGRAMS += test-fgetc
EXTRA_DIST += test-fgetc.c signature.h macros.h

## end   gnulib module fgetc-tests

## begin gnulib module float

BUILT_SOURCES += $(FLOAT_H)

# We need the following in order to create <float.h> when the system
# doesn't have one that works with the given compiler.
if GL_GENERATE_FLOAT_H
float.h: float.in.h $(top_builddir)/config.status
	$(AM_V_GEN)rm -f $@-t $@ && \
	{ echo '/* DO NOT EDIT! GENERATED AUTOMATICALLY! */' && \
	  sed -e 's|@''GUARD_PREFIX''@|GL|g' \
	      -e 's|@''INCLUDE_NEXT''@|$(INCLUDE_NEXT)|g' \
	      -e 's|@''PRAGMA_SYSTEM_HEADER''@|@PRAGMA_SYSTEM_HEADER@|g' \
	      -e 's|@''PRAGMA_COLUMNS''@|@PRAGMA_COLUMNS@|g' \
	      -e 's|@''NEXT_FLOAT_H''@|$(NEXT_FLOAT_H)|g' \
	      -e 's|@''REPLACE_ITOLD''@|$(REPLACE_ITOLD)|g' \
	      < $(srcdir)/float.in.h; \
	} > $@-t && \
	mv $@-t $@
else
float.h: $(top_builddir)/config.status
	rm -f $@
endif
MOSTLYCLEANFILES += float.h float.h-t

EXTRA_DIST += float.c float.in.h itold.c

EXTRA_libtests_a_SOURCES += float.c itold.c

## end   gnulib module float

## begin gnulib module float-tests

TESTS += test-float
check_PROGRAMS += test-float
EXTRA_DIST += test-float.c macros.h

## end   gnulib module float-tests

## begin gnulib module fpucw


EXTRA_DIST += fpucw.h

## end   gnulib module fpucw

## begin gnulib module fputc-tests

TESTS += test-fputc
check_PROGRAMS += test-fputc
EXTRA_DIST += test-fputc.c signature.h macros.h

## end   gnulib module fputc-tests

## begin gnulib module fread-tests

TESTS += test-fread
check_PROGRAMS += test-fread
EXTRA_DIST += test-fread.c signature.h macros.h

## end   gnulib module fread-tests

## begin gnulib module fwrite-tests

TESTS += test-fwrite
check_PROGRAMS += test-fwrite
EXTRA_DIST += test-fwrite.c signature.h macros.h

## end   gnulib module fwrite-tests

## begin gnulib module getpagesize


EXTRA_DIST += getpagesize.c

EXTRA_libtests_a_SOURCES += getpagesize.c

## end   gnulib module getpagesize

## begin gnulib module intprops-tests

TESTS += test-intprops
check_PROGRAMS += test-intprops
EXTRA_DIST += test-intprops.c macros.h

## end   gnulib module intprops-tests

## begin gnulib module inttostr-tests

TESTS += test-inttostr
check_PROGRAMS += test-inttostr
EXTRA_DIST += macros.h test-inttostr.c

## end   gnulib module inttostr-tests

## begin gnulib module inttypes-incomplete

BUILT_SOURCES += inttypes.h

# We need the following in order to create <inttypes.h> when the system
# doesn't have one that works with the given compiler.
inttypes.h: inttypes.in.h $(top_builddir)/config.status $(CXXDEFS_H) $(WARN_ON_USE_H) $(ARG_NONNULL_H)
	$(AM_V_GEN)rm -f $@-t $@ && \
	{ echo '/* DO NOT EDIT! GENERATED AUTOMATICALLY! */'; \
	  sed -e 's/@''HAVE_INTTYPES_H''@/$(HAVE_INTTYPES_H)/g' \
	      -e 's|@''INCLUDE_NEXT''@|$(INCLUDE_NEXT)|g' \
	      -e 's|@''PRAGMA_SYSTEM_HEADER''@|@PRAGMA_SYSTEM_HEADER@|g' \
	      -e 's|@''PRAGMA_COLUMNS''@|@PRAGMA_COLUMNS@|g' \
	      -e 's|@''NEXT_INTTYPES_H''@|$(NEXT_INTTYPES_H)|g' \
	      -e 's/@''PRI_MACROS_BROKEN''@/$(PRI_MACROS_BROKEN)/g' \
	      -e 's/@''APPLE_UNIVERSAL_BUILD''@/$(APPLE_UNIVERSAL_BUILD)/g' \
	      -e 's/@''HAVE_LONG_LONG_INT''@/$(HAVE_LONG_LONG_INT)/g' \
	      -e 's/@''HAVE_UNSIGNED_LONG_LONG_INT''@/$(HAVE_UNSIGNED_LONG_LONG_INT)/g' \
	      -e 's/@''PRIPTR_PREFIX''@/$(PRIPTR_PREFIX)/g' \
	      -e 's/@''GNULIB_IMAXABS''@/$(GNULIB_IMAXABS)/g' \
	      -e 's/@''GNULIB_IMAXDIV''@/$(GNULIB_IMAXDIV)/g' \
	      -e 's/@''GNULIB_STRTOIMAX''@/$(GNULIB_STRTOIMAX)/g' \
	      -e 's/@''GNULIB_STRTOUMAX''@/$(GNULIB_STRTOUMAX)/g' \
	      -e 's/@''HAVE_DECL_IMAXABS''@/$(HAVE_DECL_IMAXABS)/g' \
	      -e 's/@''HAVE_DECL_IMAXDIV''@/$(HAVE_DECL_IMAXDIV)/g' \
	      -e 's/@''HAVE_DECL_STRTOIMAX''@/$(HAVE_DECL_STRTOIMAX)/g' \
	      -e 's/@''HAVE_DECL_STRTOUMAX''@/$(HAVE_DECL_STRTOUMAX)/g' \
	      -e 's/@''REPLACE_STRTOIMAX''@/$(REPLACE_STRTOIMAX)/g' \
	      -e 's/@''INT32_MAX_LT_INTMAX_MAX''@/$(INT32_MAX_LT_INTMAX_MAX)/g' \
	      -e 's/@''INT64_MAX_EQ_LONG_MAX''@/$(INT64_MAX_EQ_LONG_MAX)/g' \
	      -e 's/@''UINT32_MAX_LT_UINTMAX_MAX''@/$(UINT32_MAX_LT_UINTMAX_MAX)/g' \
	      -e 's/@''UINT64_MAX_EQ_ULONG_MAX''@/$(UINT64_MAX_EQ_ULONG_MAX)/g' \
	      -e '/definitions of _GL_FUNCDECL_RPL/r $(CXXDEFS_H)' \
	      -e '/definition of _GL_ARG_NONNULL/r $(ARG_NONNULL_H)' \
	      -e '/definition of _GL_WARN_ON_USE/r $(WARN_ON_USE_H)' \
	      < $(srcdir)/inttypes.in.h; \
	} > $@-t && \
	mv $@-t $@
MOSTLYCLEANFILES += inttypes.h inttypes.h-t

EXTRA_DIST += inttypes.in.h

## end   gnulib module inttypes-incomplete

## begin gnulib module inttypes-tests

TESTS += test-inttypes
check_PROGRAMS += test-inttypes
EXTRA_DIST += test-inttypes.c

## end   gnulib module inttypes-tests

## begin gnulib module memchr-tests

TESTS += test-memchr
check_PROGRAMS += test-memchr
EXTRA_DIST += test-memchr.c zerosize-ptr.h signature.h macros.h

## end   gnulib module memchr-tests

## begin gnulib module msvc-inval


EXTRA_DIST += msvc-inval.c msvc-inval.h

EXTRA_libtests_a_SOURCES += msvc-inval.c

## end   gnulib module msvc-inval

## begin gnulib module size_max

libtests_a_SOURCES += size_max.h

## end   gnulib module size_max

## begin gnulib module snippet/arg-nonnull

# The BUILT_SOURCES created by this Makefile snippet are not used via #include
# statements but through direct file reference. Therefore this snippet must be
# present in all Makefile.am that need it. This is ensured by the applicability
# 'all' defined above.

BUILT_SOURCES += arg-nonnull.h
# The arg-nonnull.h that gets inserted into generated .h files is the same as
# build-aux/snippet/arg-nonnull.h, except that it has the copyright header cut
# off.
arg-nonnull.h: $(top_srcdir)/build-aux/snippet/arg-nonnull.h
	$(AM_V_GEN)rm -f $@-t $@ && \
	sed -n -e '/GL_ARG_NONNULL/,$$p' \
	  < $(top_srcdir)/build-aux/snippet/arg-nonnull.h \
	  > $@-t && \
	mv $@-t $@
MOSTLYCLEANFILES += arg-nonnull.h arg-nonnull.h-t

ARG_NONNULL_H=arg-nonnull.h

EXTRA_DIST += $(top_srcdir)/build-aux/snippet/arg-nonnull.h

## end   gnulib module snippet/arg-nonnull

## begin gnulib module snippet/c++defs

# The BUILT_SOURCES created by this Makefile snippet are not used via #include
# statements but through direct file reference. Therefore this snippet must be
# present in all Makefile.am that need it. This is ensured by the applicability
# 'all' defined above.

BUILT_SOURCES += c++defs.h
# The c++defs.h that gets inserted into generated .h files is the same as
# build-aux/snippet/c++defs.h, except that it has the copyright header cut off.
c++defs.h: $(top_srcdir)/build-aux/snippet/c++defs.h
	$(AM_V_GEN)rm -f $@-t $@ && \
	sed -n -e '/_GL_CXXDEFS/,$$p' \
	  < $(top_srcdir)/build-aux/snippet/c++defs.h \
	  > $@-t && \
	mv $@-t $@
MOSTLYCLEANFILES += c++defs.h c++defs.h-t

CXXDEFS_H=c++defs.h

EXTRA_DIST += $(top_srcdir)/build-aux/snippet/c++defs.h

## end   gnulib module snippet/c++defs

## begin gnulib module snippet/warn-on-use

BUILT_SOURCES += warn-on-use.h
# The warn-on-use.h that gets inserted into generated .h files is the same as
# build-aux/snippet/warn-on-use.h, except that it has the copyright header cut
# off.
warn-on-use.h: $(top_srcdir)/build-aux/snippet/warn-on-use.h
	$(AM_V_GEN)rm -f $@-t $@ && \
	sed -n -e '/^.ifndef/,$$p' \
	  < $(top_srcdir)/build-aux/snippet/warn-on-use.h \
	  > $@-t && \
	mv $@-t $@
MOSTLYCLEANFILES += warn-on-use.h warn-on-use.h-t

WARN_ON_USE_H=warn-on-use.h

EXTRA_DIST += $(top_srcdir)/build-aux/snippet/warn-on-use.h

## end   gnulib module snippet/warn-on-use

## begin gnulib module snprintf


EXTRA_DIST += snprintf.c

EXTRA_libtests_a_SOURCES += snprintf.c

## end   gnulib module snprintf

## begin gnulib module snprintf-tests

TESTS += test-snprintf
check_PROGRAMS += test-snprintf

EXTRA_DIST += test-snprintf.c signature.h macros.h

## end   gnulib module snprintf-tests

## begin gnulib module stdbool-tests

TESTS += test-stdbool
check_PROGRAMS += test-stdbool
EXTRA_DIST += test-stdbool.c

## end   gnulib module stdbool-tests

## begin gnulib module stddef-tests

TESTS += test-stddef
check_PROGRAMS += test-stddef
EXTRA_DIST += test-stddef.c

## end   gnulib module stddef-tests

## begin gnulib module stdint-tests

TESTS += test-stdint
check_PROGRAMS += test-stdint
EXTRA_DIST += test-stdint.c

## end   gnulib module stdint-tests

## begin gnulib module stdio

BUILT_SOURCES += stdio.h

# We need the following in order to create <stdio.h> when the system
# doesn't have one that works with the given compiler.
stdio.h: stdio.in.h $(top_builddir)/config.status $(CXXDEFS_H) $(ARG_NONNULL_H) $(WARN_ON_USE_H)
	$(AM_V_GEN)rm -f $@-t $@ && \
	{ echo '/* DO NOT EDIT! GENERATED AUTOMATICALLY! */' && \
	  sed -e 's|@''GUARD_PREFIX''@|GL|g' \
	      -e 's|@''INCLUDE_NEXT''@|$(INCLUDE_NEXT)|g' \
	      -e 's|@''PRAGMA_SYSTEM_HEADER''@|@PRAGMA_SYSTEM_HEADER@|g' \
	      -e 's|@''PRAGMA_COLUMNS''@|@PRAGMA_COLUMNS@|g' \
	      -e 's|@''NEXT_STDIO_H''@|$(NEXT_STDIO_H)|g' \
	      -e 's/@''GNULIB_DPRINTF''@/$(GNULIB_DPRINTF)/g' \
	      -e 's/@''GNULIB_FCLOSE''@/$(GNULIB_FCLOSE)/g' \
	      -e 's/@''GNULIB_FDOPEN''@/$(GNULIB_FDOPEN)/g' \
	      -e 's/@''GNULIB_FFLUSH''@/$(GNULIB_FFLUSH)/g' \
	      -e 's/@''GNULIB_FGETC''@/$(GNULIB_FGETC)/g' \
	      -e 's/@''GNULIB_FGETS''@/$(GNULIB_FGETS)/g' \
	      -e 's/@''GNULIB_FOPEN''@/$(GNULIB_FOPEN)/g' \
	      -e 's/@''GNULIB_FPRINTF''@/$(GNULIB_FPRINTF)/g' \
	      -e 's/@''GNULIB_FPRINTF_POSIX''@/$(GNULIB_FPRINTF_POSIX)/g' \
	      -e 's/@''GNULIB_FPURGE''@/$(GNULIB_FPURGE)/g' \
	      -e 's/@''GNULIB_FPUTC''@/$(GNULIB_FPUTC)/g' \
	      -e 's/@''GNULIB_FPUTS''@/$(GNULIB_FPUTS)/g' \
	      -e 's/@''GNULIB_FREAD''@/$(GNULIB_FREAD)/g' \
	      -e 's/@''GNULIB_FREOPEN''@/$(GNULIB_FREOPEN)/g' \
	      -e 's/@''GNULIB_FSCANF''@/$(GNULIB_FSCANF)/g' \
	      -e 's/@''GNULIB_FSEEK''@/$(GNULIB_FSEEK)/g' \
	      -e 's/@''GNULIB_FSEEKO''@/$(GNULIB_FSEEKO)/g' \
	      -e 's/@''GNULIB_FTELL''@/$(GNULIB_FTELL)/g' \
	      -e 's/@''GNULIB_FTELLO''@/$(GNULIB_FTELLO)/g' \
	      -e 's/@''GNULIB_FWRITE''@/$(GNULIB_FWRITE)/g' \
	      -e 's/@''GNULIB_GETC''@/$(GNULIB_GETC)/g' \
	      -e 's/@''GNULIB_GETCHAR''@/$(GNULIB_GETCHAR)/g' \
	      -e 's/@''GNULIB_GETDELIM''@/$(GNULIB_GETDELIM)/g' \
	      -e 's/@''GNULIB_GETLINE''@/$(GNULIB_GETLINE)/g' \
	      -e 's/@''GNULIB_OBSTACK_PRINTF''@/$(GNULIB_OBSTACK_PRINTF)/g' \
	      -e 's/@''GNULIB_OBSTACK_PRINTF_POSIX''@/$(GNULIB_OBSTACK_PRINTF_POSIX)/g' \
	      -e 's/@''GNULIB_PCLOSE''@/$(GNULIB_PCLOSE)/g' \
	      -e 's/@''GNULIB_PERROR''@/$(GNULIB_PERROR)/g' \
	      -e 's/@''GNULIB_POPEN''@/$(GNULIB_POPEN)/g' \
	      -e 's/@''GNULIB_PRINTF''@/$(GNULIB_PRINTF)/g' \
	      -e 's/@''GNULIB_PRINTF_POSIX''@/$(GNULIB_PRINTF_POSIX)/g' \
	      -e 's/@''GNULIB_PUTC''@/$(GNULIB_PUTC)/g' \
	      -e 's/@''GNULIB_PUTCHAR''@/$(GNULIB_PUTCHAR)/g' \
	      -e 's/@''GNULIB_PUTS''@/$(GNULIB_PUTS)/g' \
	      -e 's/@''GNULIB_REMOVE''@/$(GNULIB_REMOVE)/g' \
	      -e 's/@''GNULIB_RENAME''@/$(GNULIB_RENAME)/g' \
	      -e 's/@''GNULIB_RENAMEAT''@/$(GNULIB_RENAMEAT)/g' \
	      -e 's/@''GNULIB_SCANF''@/$(GNULIB_SCANF)/g' \
	      -e 's/@''GNULIB_SNPRINTF''@/$(GNULIB_SNPRINTF)/g' \
	      -e 's/@''GNULIB_SPRINTF_POSIX''@/$(GNULIB_SPRINTF_POSIX)/g' \
	      -e 's/@''GNULIB_STDIO_H_NONBLOCKING''@/$(GNULIB_STDIO_H_NONBLOCKING)/g' \
	      -e 's/@''GNULIB_STDIO_H_SIGPIPE''@/$(GNULIB_STDIO_H_SIGPIPE)/g' \
	      -e 's/@''GNULIB_TMPFILE''@/$(GNULIB_TMPFILE)/g' \
	      -e 's/@''GNULIB_VASPRINTF''@/$(GNULIB_VASPRINTF)/g' \
	      -e 's/@''GNULIB_VDPRINTF''@/$(GNULIB_VDPRINTF)/g' \
	      -e 's/@''GNULIB_VFPRINTF''@/$(GNULIB_VFPRINTF)/g' \
	      -e 's/@''GNULIB_VFPRINTF_POSIX''@/$(GNULIB_VFPRINTF_POSIX)/g' \
	      -e 's/@''GNULIB_VFSCANF''@/$(GNULIB_VFSCANF)/g' \
	      -e 's/@''GNULIB_VSCANF''@/$(GNULIB_VSCANF)/g' \
	      -e 's/@''GNULIB_VPRINTF''@/$(GNULIB_VPRINTF)/g' \
	      -e 's/@''GNULIB_VPRINTF_POSIX''@/$(GNULIB_VPRINTF_POSIX)/g' \
	      -e 's/@''GNULIB_VSNPRINTF''@/$(GNULIB_VSNPRINTF)/g' \
	      -e 's/@''GNULIB_VSPRINTF_POSIX''@/$(GNULIB_VSPRINTF_POSIX)/g' \
	      < $(srcdir)/stdio.in.h | \
	  sed -e 's|@''HAVE_DECL_FPURGE''@|$(HAVE_DECL_FPURGE)|g' \
	      -e 's|@''HAVE_DECL_FSEEKO''@|$(HAVE_DECL_FSEEKO)|g' \
	      -e 's|@''HAVE_DECL_FTELLO''@|$(HAVE_DECL_FTELLO)|g' \
	      -e 's|@''HAVE_DECL_GETDELIM''@|$(HAVE_DECL_GETDELIM)|g' \
	      -e 's|@''HAVE_DECL_GETLINE''@|$(HAVE_DECL_GETLINE)|g' \
	      -e 's|@''HAVE_DECL_OBSTACK_PRINTF''@|$(HAVE_DECL_OBSTACK_PRINTF)|g' \
	      -e 's|@''HAVE_DECL_SNPRINTF''@|$(HAVE_DECL_SNPRINTF)|g' \
	      -e 's|@''HAVE_DECL_VSNPRINTF''@|$(HAVE_DECL_VSNPRINTF)|g' \
	      -e 's|@''HAVE_DPRINTF''@|$(HAVE_DPRINTF)|g' \
	      -e 's|@''HAVE_FSEEKO''@|$(HAVE_FSEEKO)|g' \
	      -e 's|@''HAVE_FTELLO''@|$(HAVE_FTELLO)|g' \
	      -e 's|@''HAVE_PCLOSE''@|$(HAVE_PCLOSE)|g' \
	      -e 's|@''HAVE_POPEN''@|$(HAVE_POPEN)|g' \
	      -e 's|@''HAVE_RENAMEAT''@|$(HAVE_RENAMEAT)|g' \
	      -e 's|@''HAVE_VASPRINTF''@|$(HAVE_VASPRINTF)|g' \
	      -e 's|@''HAVE_VDPRINTF''@|$(HAVE_VDPRINTF)|g' \
	      -e 's|@''REPLACE_DPRINTF''@|$(REPLACE_DPRINTF)|g' \
	      -e 's|@''REPLACE_FCLOSE''@|$(REPLACE_FCLOSE)|g' \
	      -e 's|@''REPLACE_FDOPEN''@|$(REPLACE_FDOPEN)|g' \
	      -e 's|@''REPLACE_FFLUSH''@|$(REPLACE_FFLUSH)|g' \
	      -e 's|@''REPLACE_FOPEN''@|$(REPLACE_FOPEN)|g' \
	      -e 's|@''REPLACE_FPRINTF''@|$(REPLACE_FPRINTF)|g' \
	      -e 's|@''REPLACE_FPURGE''@|$(REPLACE_FPURGE)|g' \
	      -e 's|@''REPLACE_FREOPEN''@|$(REPLACE_FREOPEN)|g' \
	      -e 's|@''REPLACE_FSEEK''@|$(REPLACE_FSEEK)|g' \
	      -e 's|@''REPLACE_FSEEKO''@|$(REPLACE_FSEEKO)|g' \
	      -e 's|@''REPLACE_FTELL''@|$(REPLACE_FTELL)|g' \
	      -e 's|@''REPLACE_FTELLO''@|$(REPLACE_FTELLO)|g' \
	      -e 's|@''REPLACE_GETDELIM''@|$(REPLACE_GETDELIM)|g' \
	      -e 's|@''REPLACE_GETLINE''@|$(REPLACE_GETLINE)|g' \
	      -e 's|@''REPLACE_OBSTACK_PRINTF''@|$(REPLACE_OBSTACK_PRINTF)|g' \
	      -e 's|@''REPLACE_PERROR''@|$(REPLACE_PERROR)|g' \
	      -e 's|@''REPLACE_POPEN''@|$(REPLACE_POPEN)|g' \
	      -e 's|@''REPLACE_PRINTF''@|$(REPLACE_PRINTF)|g' \
	      -e 's|@''REPLACE_REMOVE''@|$(REPLACE_REMOVE)|g' \
	      -e 's|@''REPLACE_RENAME''@|$(REPLACE_RENAME)|g' \
	      -e 's|@''REPLACE_RENAMEAT''@|$(REPLACE_RENAMEAT)|g' \
	      -e 's|@''REPLACE_SNPRINTF''@|$(REPLACE_SNPRINTF)|g' \
	      -e 's|@''REPLACE_SPRINTF''@|$(REPLACE_SPRINTF)|g' \
	      -e 's|@''REPLACE_STDIO_READ_FUNCS''@|$(REPLACE_STDIO_READ_FUNCS)|g' \
	      -e 's|@''REPLACE_STDIO_WRITE_FUNCS''@|$(REPLACE_STDIO_WRITE_FUNCS)|g' \
	      -e 's|@''REPLACE_TMPFILE''@|$(REPLACE_TMPFILE)|g' \
	      -e 's|@''REPLACE_VASPRINTF''@|$(REPLACE_VASPRINTF)|g' \
	      -e 's|@''REPLACE_VDPRINTF''@|$(REPLACE_VDPRINTF)|g' \
	      -e 's|@''REPLACE_VFPRINTF''@|$(REPLACE_VFPRINTF)|g' \
	      -e 's|@''REPLACE_VPRINTF''@|$(REPLACE_VPRINTF)|g' \
	      -e 's|@''REPLACE_VSNPRINTF''@|$(REPLACE_VSNPRINTF)|g' \
	      -e 's|@''REPLACE_VSPRINTF''@|$(REPLACE_VSPRINTF)|g' \
	      -e 's|@''ASM_SYMBOL_PREFIX''@|$(ASM_SYMBOL_PREFIX)|g' \
	      -e '/definitions of _GL_FUNCDECL_RPL/r $(CXXDEFS_H)' \
	      -e '/definition of _GL_ARG_NONNULL/r $(ARG_NONNULL_H)' \
	      -e '/definition of _GL_WARN_ON_USE/r $(WARN_ON_USE_H)'; \
	} > $@-t && \
	mv $@-t $@
MOSTLYCLEANFILES += stdio.h stdio.h-t

EXTRA_DIST += stdio.in.h

## end   gnulib module stdio

## begin gnulib module stdio-tests

TESTS += test-stdio
check_PROGRAMS += test-stdio
EXTRA_DIST += test-stdio.c

## end   gnulib module stdio-tests

## begin gnulib module string-tests

TESTS += test-string
check_PROGRAMS += test-string
EXTRA_DIST += test-string.c

## end   gnulib module string-tests

## begin gnulib module strverscmp-tests

TESTS += test-strverscmp
check_PROGRAMS += test-strverscmp
EXTRA_DIST += test-strverscmp.c signature.h macros.h

## end   gnulib module strverscmp-tests

## begin gnulib module sys_types

BUILT_SOURCES += sys/types.h

# We need the following in order to create <sys/types.h> when the system
# doesn't have one that works with the given compiler.
sys/types.h: sys_types.in.h $(top_builddir)/config.status
	$(AM_V_at)$(MKDIR_P) sys
	$(AM_V_GEN)rm -f $@-t $@ && \
	{ echo '/* DO NOT EDIT! GENERATED AUTOMATICALLY! */'; \
	  sed -e 's|@''GUARD_PREFIX''@|GL|g' \
	      -e 's|@''INCLUDE_NEXT''@|$(INCLUDE_NEXT)|g' \
	      -e 's|@''PRAGMA_SYSTEM_HEADER''@|@PRAGMA_SYSTEM_HEADER@|g' \
	      -e 's|@''PRAGMA_COLUMNS''@|@PRAGMA_COLUMNS@|g' \
	      -e 's|@''NEXT_SYS_TYPES_H''@|$(NEXT_SYS_TYPES_H)|g' \
	      -e 's|@''WINDOWS_64_BIT_OFF_T''@|$(WINDOWS_64_BIT_OFF_T)|g' \
	      < $(srcdir)/sys_types.in.h; \
	} > $@-t && \
	mv $@-t $@
MOSTLYCLEANFILES += sys/types.h sys/types.h-t

EXTRA_DIST += sys_types.in.h

## end   gnulib module sys_types

## begin gnulib module sys_types-tests

TESTS += test-sys_types
check_PROGRAMS += test-sys_types
EXTRA_DIST += test-sys_types.c

## end   gnulib module sys_types-tests

## begin gnulib module test-framework-sh-tests

TESTS += test-init.sh
EXTRA_DIST += init.sh
EXTRA_DIST += test-init.sh

## end   gnulib module test-framework-sh-tests

## begin gnulib module unistd

BUILT_SOURCES += unistd.h
libtests_a_SOURCES += unistd.c

# We need the following in order to create an empty placeholder for
# <unistd.h> when the system doesn't have one.
unistd.h: unistd.in.h $(top_builddir)/config.status $(CXXDEFS_H) $(ARG_NONNULL_H) $(WARN_ON_USE_H)
	$(AM_V_GEN)rm -f $@-t $@ && \
	{ echo '/* DO NOT EDIT! GENERATED AUTOMATICALLY! */'; \
	  sed -e 's|@''GUARD_PREFIX''@|GL|g' \
	      -e 's|@''HAVE_UNISTD_H''@|$(HAVE_UNISTD_H)|g' \
	      -e 's|@''INCLUDE_NEXT''@|$(INCLUDE_NEXT)|g' \
	      -e 's|@''PRAGMA_SYSTEM_HEADER''@|@PRAGMA_SYSTEM_HEADER@|g' \
	      -e 's|@''PRAGMA_COLUMNS''@|@PRAGMA_COLUMNS@|g' \
	      -e 's|@''NEXT_UNISTD_H''@|$(NEXT_UNISTD_H)|g' \
	      -e 's|@''WINDOWS_64_BIT_OFF_T''@|$(WINDOWS_64_BIT_OFF_T)|g' \
	      -e 's/@''GNULIB_CHDIR''@/$(GNULIB_CHDIR)/g' \
	      -e 's/@''GNULIB_CHOWN''@/$(GNULIB_CHOWN)/g' \
	      -e 's/@''GNULIB_CLOSE''@/$(GNULIB_CLOSE)/g' \
	      -e 's/@''GNULIB_DUP''@/$(GNULIB_DUP)/g' \
	      -e 's/@''GNULIB_DUP2''@/$(GNULIB_DUP2)/g' \
	      -e 's/@''GNULIB_DUP3''@/$(GNULIB_DUP3)/g' \
	      -e 's/@''GNULIB_ENVIRON''@/$(GNULIB_ENVIRON)/g' \
	      -e 's/@''GNULIB_EUIDACCESS''@/$(GNULIB_EUIDACCESS)/g' \
	      -e 's/@''GNULIB_FACCESSAT''@/$(GNULIB_FACCESSAT)/g' \
	      -e 's/@''GNULIB_FCHDIR''@/$(GNULIB_FCHDIR)/g' \
	      -e 's/@''GNULIB_FCHOWNAT''@/$(GNULIB_FCHOWNAT)/g' \
	      -e 's/@''GNULIB_FDATASYNC''@/$(GNULIB_FDATASYNC)/g' \
	      -e 's/@''GNULIB_FSYNC''@/$(GNULIB_FSYNC)/g' \
	      -e 's/@''GNULIB_FTRUNCATE''@/$(GNULIB_FTRUNCATE)/g' \
	      -e 's/@''GNULIB_GETCWD''@/$(GNULIB_GETCWD)/g' \
	      -e 's/@''GNULIB_GETDOMAINNAME''@/$(GNULIB_GETDOMAINNAME)/g' \
	      -e 's/@''GNULIB_GETDTABLESIZE''@/$(GNULIB_GETDTABLESIZE)/g' \
	      -e 's/@''GNULIB_GETGROUPS''@/$(GNULIB_GETGROUPS)/g' \
	      -e 's/@''GNULIB_GETHOSTNAME''@/$(GNULIB_GETHOSTNAME)/g' \
	      -e 's/@''GNULIB_GETLOGIN''@/$(GNULIB_GETLOGIN)/g' \
	      -e 's/@''GNULIB_GETLOGIN_R''@/$(GNULIB_GETLOGIN_R)/g' \
	      -e 's/@''GNULIB_GETPAGESIZE''@/$(GNULIB_GETPAGESIZE)/g' \
	      -e 's/@''GNULIB_GETUSERSHELL''@/$(GNULIB_GETUSERSHELL)/g' \
	      -e 's/@''GNULIB_GROUP_MEMBER''@/$(GNULIB_GROUP_MEMBER)/g' \
	      -e 's/@''GNULIB_ISATTY''@/$(GNULIB_ISATTY)/g' \
	      -e 's/@''GNULIB_LCHOWN''@/$(GNULIB_LCHOWN)/g' \
	      -e 's/@''GNULIB_LINK''@/$(GNULIB_LINK)/g' \
	      -e 's/@''GNULIB_LINKAT''@/$(GNULIB_LINKAT)/g' \
	      -e 's/@''GNULIB_LSEEK''@/$(GNULIB_LSEEK)/g' \
	      -e 's/@''GNULIB_PIPE''@/$(GNULIB_PIPE)/g' \
	      -e 's/@''GNULIB_PIPE2''@/$(GNULIB_PIPE2)/g' \
	      -e 's/@''GNULIB_PREAD''@/$(GNULIB_PREAD)/g' \
	      -e 's/@''GNULIB_PWRITE''@/$(GNULIB_PWRITE)/g' \
	      -e 's/@''GNULIB_READ''@/$(GNULIB_READ)/g' \
	      -e 's/@''GNULIB_READLINK''@/$(GNULIB_READLINK)/g' \
	      -e 's/@''GNULIB_READLINKAT''@/$(GNULIB_READLINKAT)/g' \
	      -e 's/@''GNULIB_RMDIR''@/$(GNULIB_RMDIR)/g' \
	      -e 's/@''GNULIB_SETHOSTNAME''@/$(GNULIB_SETHOSTNAME)/g' \
	      -e 's/@''GNULIB_SLEEP''@/$(GNULIB_SLEEP)/g' \
	      -e 's/@''GNULIB_SYMLINK''@/$(GNULIB_SYMLINK)/g' \
	      -e 's/@''GNULIB_SYMLINKAT''@/$(GNULIB_SYMLINKAT)/g' \
	      -e 's/@''GNULIB_TTYNAME_R''@/$(GNULIB_TTYNAME_R)/g' \
	      -e 's/@''GNULIB_UNISTD_H_GETOPT''@/0$(GNULIB_GL_UNISTD_H_GETOPT)/g' \
	      -e 's/@''GNULIB_UNISTD_H_NONBLOCKING''@/$(GNULIB_UNISTD_H_NONBLOCKING)/g' \
	      -e 's/@''GNULIB_UNISTD_H_SIGPIPE''@/$(GNULIB_UNISTD_H_SIGPIPE)/g' \
	      -e 's/@''GNULIB_UNLINK''@/$(GNULIB_UNLINK)/g' \
	      -e 's/@''GNULIB_UNLINKAT''@/$(GNULIB_UNLINKAT)/g' \
	      -e 's/@''GNULIB_USLEEP''@/$(GNULIB_USLEEP)/g' \
	      -e 's/@''GNULIB_WRITE''@/$(GNULIB_WRITE)/g' \
	      < $(srcdir)/unistd.in.h | \
	  sed -e 's|@''HAVE_CHOWN''@|$(HAVE_CHOWN)|g' \
	      -e 's|@''HAVE_DUP2''@|$(HAVE_DUP2)|g' \
	      -e 's|@''HAVE_DUP3''@|$(HAVE_DUP3)|g' \
	      -e 's|@''HAVE_EUIDACCESS''@|$(HAVE_EUIDACCESS)|g' \
	      -e 's|@''HAVE_FACCESSAT''@|$(HAVE_FACCESSAT)|g' \
	      -e 's|@''HAVE_FCHDIR''@|$(HAVE_FCHDIR)|g' \
	      -e 's|@''HAVE_FCHOWNAT''@|$(HAVE_FCHOWNAT)|g' \
	      -e 's|@''HAVE_FDATASYNC''@|$(HAVE_FDATASYNC)|g' \
	      -e 's|@''HAVE_FSYNC''@|$(HAVE_FSYNC)|g' \
	      -e 's|@''HAVE_FTRUNCATE''@|$(HAVE_FTRUNCATE)|g' \
	      -e 's|@''HAVE_GETDTABLESIZE''@|$(HAVE_GETDTABLESIZE)|g' \
	      -e 's|@''HAVE_GETGROUPS''@|$(HAVE_GETGROUPS)|g' \
	      -e 's|@''HAVE_GETHOSTNAME''@|$(HAVE_GETHOSTNAME)|g' \
	      -e 's|@''HAVE_GETLOGIN''@|$(HAVE_GETLOGIN)|g' \
	      -e 's|@''HAVE_GETPAGESIZE''@|$(HAVE_GETPAGESIZE)|g' \
	      -e 's|@''HAVE_GROUP_MEMBER''@|$(HAVE_GROUP_MEMBER)|g' \
	      -e 's|@''HAVE_LCHOWN''@|$(HAVE_LCHOWN)|g' \
	      -e 's|@''HAVE_LINK''@|$(HAVE_LINK)|g' \
	      -e 's|@''HAVE_LINKAT''@|$(HAVE_LINKAT)|g' \
	      -e 's|@''HAVE_PIPE''@|$(HAVE_PIPE)|g' \
	      -e 's|@''HAVE_PIPE2''@|$(HAVE_PIPE2)|g' \
	      -e 's|@''HAVE_PREAD''@|$(HAVE_PREAD)|g' \
	      -e 's|@''HAVE_PWRITE''@|$(HAVE_PWRITE)|g' \
	      -e 's|@''HAVE_READLINK''@|$(HAVE_READLINK)|g' \
	      -e 's|@''HAVE_READLINKAT''@|$(HAVE_READLINKAT)|g' \
	      -e 's|@''HAVE_SETHOSTNAME''@|$(HAVE_SETHOSTNAME)|g' \
	      -e 's|@''HAVE_SLEEP''@|$(HAVE_SLEEP)|g' \
	      -e 's|@''HAVE_SYMLINK''@|$(HAVE_SYMLINK)|g' \
	      -e 's|@''HAVE_SYMLINKAT''@|$(HAVE_SYMLINKAT)|g' \
	      -e 's|@''HAVE_UNLINKAT''@|$(HAVE_UNLINKAT)|g' \
	      -e 's|@''HAVE_USLEEP''@|$(HAVE_USLEEP)|g' \
	      -e 's|@''HAVE_DECL_ENVIRON''@|$(HAVE_DECL_ENVIRON)|g' \
	      -e 's|@''HAVE_DECL_FCHDIR''@|$(HAVE_DECL_FCHDIR)|g' \
	      -e 's|@''HAVE_DECL_FDATASYNC''@|$(HAVE_DECL_FDATASYNC)|g' \
	      -e 's|@''HAVE_DECL_GETDOMAINNAME''@|$(HAVE_DECL_GETDOMAINNAME)|g' \
	      -e 's|@''HAVE_DECL_GETLOGIN_R''@|$(HAVE_DECL_GETLOGIN_R)|g' \
	      -e 's|@''HAVE_DECL_GETPAGESIZE''@|$(HAVE_DECL_GETPAGESIZE)|g' \
	      -e 's|@''HAVE_DECL_GETUSERSHELL''@|$(HAVE_DECL_GETUSERSHELL)|g' \
	      -e 's|@''HAVE_DECL_SETHOSTNAME''@|$(HAVE_DECL_SETHOSTNAME)|g' \
	      -e 's|@''HAVE_DECL_TTYNAME_R''@|$(HAVE_DECL_TTYNAME_R)|g' \
	      -e 's|@''HAVE_OS_H''@|$(HAVE_OS_H)|g' \
	      -e 's|@''HAVE_SYS_PARAM_H''@|$(HAVE_SYS_PARAM_H)|g' \
	  | \
	  sed -e 's|@''REPLACE_CHOWN''@|$(REPLACE_CHOWN)|g' \
	      -e 's|@''REPLACE_CLOSE''@|$(REPLACE_CLOSE)|g' \
	      -e 's|@''REPLACE_DUP''@|$(REPLACE_DUP)|g' \
	      -e 's|@''REPLACE_DUP2''@|$(REPLACE_DUP2)|g' \
	      -e 's|@''REPLACE_FCHOWNAT''@|$(REPLACE_FCHOWNAT)|g' \
	      -e 's|@''REPLACE_FTRUNCATE''@|$(REPLACE_FTRUNCATE)|g' \
	      -e 's|@''REPLACE_GETCWD''@|$(REPLACE_GETCWD)|g' \
	      -e 's|@''REPLACE_GETDOMAINNAME''@|$(REPLACE_GETDOMAINNAME)|g' \
	      -e 's|@''REPLACE_GETLOGIN_R''@|$(REPLACE_GETLOGIN_R)|g' \
	      -e 's|@''REPLACE_GETGROUPS''@|$(REPLACE_GETGROUPS)|g' \
	      -e 's|@''REPLACE_GETPAGESIZE''@|$(REPLACE_GETPAGESIZE)|g' \
	      -e 's|@''REPLACE_ISATTY''@|$(REPLACE_ISATTY)|g' \
	      -e 's|@''REPLACE_LCHOWN''@|$(REPLACE_LCHOWN)|g' \
	      -e 's|@''REPLACE_LINK''@|$(REPLACE_LINK)|g' \
	      -e 's|@''REPLACE_LINKAT''@|$(REPLACE_LINKAT)|g' \
	      -e 's|@''REPLACE_LSEEK''@|$(REPLACE_LSEEK)|g' \
	      -e 's|@''REPLACE_PREAD''@|$(REPLACE_PREAD)|g' \
	      -e 's|@''REPLACE_PWRITE''@|$(REPLACE_PWRITE)|g' \
	      -e 's|@''REPLACE_READ''@|$(REPLACE_READ)|g' \
	      -e 's|@''REPLACE_READLINK''@|$(REPLACE_READLINK)|g' \
	      -e 's|@''REPLACE_RMDIR''@|$(REPLACE_RMDIR)|g' \
	      -e 's|@''REPLACE_SLEEP''@|$(REPLACE_SLEEP)|g' \
	      -e 's|@''REPLACE_SYMLINK''@|$(REPLACE_SYMLINK)|g' \
	      -e 's|@''REPLACE_TTYNAME_R''@|$(REPLACE_TTYNAME_R)|g' \
	      -e 's|@''REPLACE_UNLINK''@|$(REPLACE_UNLINK)|g' \
	      -e 's|@''REPLACE_UNLINKAT''@|$(REPLACE_UNLINKAT)|g' \
	      -e 's|@''REPLACE_USLEEP''@|$(REPLACE_USLEEP)|g' \
	      -e 's|@''REPLACE_WRITE''@|$(REPLACE_WRITE)|g' \
	      -e 's|@''UNISTD_H_HAVE_WINSOCK2_H''@|$(UNISTD_H_HAVE_WINSOCK2_H)|g' \
	      -e 's|@''UNISTD_H_HAVE_WINSOCK2_H_AND_USE_SOCKETS''@|$(UNISTD_H_HAVE_WINSOCK2_H_AND_USE_SOCKETS)|g' \
	      -e '/definitions of _GL_FUNCDECL_RPL/r $(CXXDEFS_H)' \
	      -e '/definition of _GL_ARG_NONNULL/r $(ARG_NONNULL_H)' \
	      -e '/definition of _GL_WARN_ON_USE/r $(WARN_ON_USE_H)'; \
	} > $@-t && \
	mv $@-t $@
MOSTLYCLEANFILES += unistd.h unistd.h-t

EXTRA_DIST += unistd.in.h

## end   gnulib module unistd

## begin gnulib module unistd-tests

TESTS += test-unistd
check_PROGRAMS += test-unistd
EXTRA_DIST += test-unistd.c

## end   gnulib module unistd-tests

## begin gnulib module vasnprintf


EXTRA_DIST += asnprintf.c float+.h printf-args.c printf-args.h printf-parse.c printf-parse.h vasnprintf.c vasnprintf.h

EXTRA_libtests_a_SOURCES += asnprintf.c printf-args.c printf-parse.c vasnprintf.c

## end   gnulib module vasnprintf

## begin gnulib module vasnprintf-tests

TESTS += test-vasnprintf
check_PROGRAMS += test-vasnprintf

EXTRA_DIST += test-vasnprintf.c macros.h

## end   gnulib module vasnprintf-tests

## begin gnulib module verify


EXTRA_DIST += verify.h

## end   gnulib module verify

## begin gnulib module verify-tests

TESTS_ENVIRONMENT += MAKE='$(MAKE)'
TESTS += test-verify test-verify.sh
check_PROGRAMS += test-verify
EXTRA_DIST += test-verify.c test-verify.sh

## end   gnulib module verify-tests

## begin gnulib module wchar

BUILT_SOURCES += wchar.h

# We need the following in order to create <wchar.h> when the system
# version does not work standalone.
wchar.h: wchar.in.h $(top_builddir)/config.status $(CXXDEFS_H) $(ARG_NONNULL_H) $(WARN_ON_USE_H)
	$(AM_V_GEN)rm -f $@-t $@ && \
	{ echo '/* DO NOT EDIT! GENERATED AUTOMATICALLY! */'; \
	  sed -e 's|@''GUARD_PREFIX''@|GL|g' \
	      -e 's|@''INCLUDE_NEXT''@|$(INCLUDE_NEXT)|g' \
	      -e 's|@''PRAGMA_SYSTEM_HEADER''@|@PRAGMA_SYSTEM_HEADER@|g' \
	      -e 's|@''PRAGMA_COLUMNS''@|@PRAGMA_COLUMNS@|g' \
	      -e 's|@''HAVE_FEATURES_H''@|$(HAVE_FEATURES_H)|g' \
	      -e 's|@''NEXT_WCHAR_H''@|$(NEXT_WCHAR_H)|g' \
	      -e 's|@''HAVE_WCHAR_H''@|$(HAVE_WCHAR_H)|g' \
	      -e 's/@''GNULIB_BTOWC''@/$(GNULIB_BTOWC)/g' \
	      -e 's/@''GNULIB_WCTOB''@/$(GNULIB_WCTOB)/g' \
	      -e 's/@''GNULIB_MBSINIT''@/$(GNULIB_MBSINIT)/g' \
	      -e 's/@''GNULIB_MBRTOWC''@/$(GNULIB_MBRTOWC)/g' \
	      -e 's/@''GNULIB_MBRLEN''@/$(GNULIB_MBRLEN)/g' \
	      -e 's/@''GNULIB_MBSRTOWCS''@/$(GNULIB_MBSRTOWCS)/g' \
	      -e 's/@''GNULIB_MBSNRTOWCS''@/$(GNULIB_MBSNRTOWCS)/g' \
	      -e 's/@''GNULIB_WCRTOMB''@/$(GNULIB_WCRTOMB)/g' \
	      -e 's/@''GNULIB_WCSRTOMBS''@/$(GNULIB_WCSRTOMBS)/g' \
	      -e 's/@''GNULIB_WCSNRTOMBS''@/$(GNULIB_WCSNRTOMBS)/g' \
	      -e 's/@''GNULIB_WCWIDTH''@/$(GNULIB_WCWIDTH)/g' \
	      -e 's/@''GNULIB_WMEMCHR''@/$(GNULIB_WMEMCHR)/g' \
	      -e 's/@''GNULIB_WMEMCMP''@/$(GNULIB_WMEMCMP)/g' \
	      -e 's/@''GNULIB_WMEMCPY''@/$(GNULIB_WMEMCPY)/g' \
	      -e 's/@''GNULIB_WMEMMOVE''@/$(GNULIB_WMEMMOVE)/g' \
	      -e 's/@''GNULIB_WMEMSET''@/$(GNULIB_WMEMSET)/g' \
	      -e 's/@''GNULIB_WCSLEN''@/$(GNULIB_WCSLEN)/g' \
	      -e 's/@''GNULIB_WCSNLEN''@/$(GNULIB_WCSNLEN)/g' \
	      -e 's/@''GNULIB_WCSCPY''@/$(GNULIB_WCSCPY)/g' \
	      -e 's/@''GNULIB_WCPCPY''@/$(GNULIB_WCPCPY)/g' \
	      -e 's/@''GNULIB_WCSNCPY''@/$(GNULIB_WCSNCPY)/g' \
	      -e 's/@''GNULIB_WCPNCPY''@/$(GNULIB_WCPNCPY)/g' \
	      -e 's/@''GNULIB_WCSCAT''@/$(GNULIB_WCSCAT)/g' \
	      -e 's/@''GNULIB_WCSNCAT''@/$(GNULIB_WCSNCAT)/g' \
	      -e 's/@''GNULIB_WCSCMP''@/$(GNULIB_WCSCMP)/g' \
	      -e 's/@''GNULIB_WCSNCMP''@/$(GNULIB_WCSNCMP)/g' \
	      -e 's/@''GNULIB_WCSCASECMP''@/$(GNULIB_WCSCASECMP)/g' \
	      -e 's/@''GNULIB_WCSNCASECMP''@/$(GNULIB_WCSNCASECMP)/g' \
	      -e 's/@''GNULIB_WCSCOLL''@/$(GNULIB_WCSCOLL)/g' \
	      -e 's/@''GNULIB_WCSXFRM''@/$(GNULIB_WCSXFRM)/g' \
	      -e 's/@''GNULIB_WCSDUP''@/$(GNULIB_WCSDUP)/g' \
	      -e 's/@''GNULIB_WCSCHR''@/$(GNULIB_WCSCHR)/g' \
	      -e 's/@''GNULIB_WCSRCHR''@/$(GNULIB_WCSRCHR)/g' \
	      -e 's/@''GNULIB_WCSCSPN''@/$(GNULIB_WCSCSPN)/g' \
	      -e 's/@''GNULIB_WCSSPN''@/$(GNULIB_WCSSPN)/g' \
	      -e 's/@''GNULIB_WCSPBRK''@/$(GNULIB_WCSPBRK)/g' \
	      -e 's/@''GNULIB_WCSSTR''@/$(GNULIB_WCSSTR)/g' \
	      -e 's/@''GNULIB_WCSTOK''@/$(GNULIB_WCSTOK)/g' \
	      -e 's/@''GNULIB_WCSWIDTH''@/$(GNULIB_WCSWIDTH)/g' \
	      < $(srcdir)/wchar.in.h | \
	  sed -e 's|@''HAVE_WINT_T''@|$(HAVE_WINT_T)|g' \
	      -e 's|@''HAVE_BTOWC''@|$(HAVE_BTOWC)|g' \
	      -e 's|@''HAVE_MBSINIT''@|$(HAVE_MBSINIT)|g' \
	      -e 's|@''HAVE_MBRTOWC''@|$(HAVE_MBRTOWC)|g' \
	      -e 's|@''HAVE_MBRLEN''@|$(HAVE_MBRLEN)|g' \
	      -e 's|@''HAVE_MBSRTOWCS''@|$(HAVE_MBSRTOWCS)|g' \
	      -e 's|@''HAVE_MBSNRTOWCS''@|$(HAVE_MBSNRTOWCS)|g' \
	      -e 's|@''HAVE_WCRTOMB''@|$(HAVE_WCRTOMB)|g' \
	      -e 's|@''HAVE_WCSRTOMBS''@|$(HAVE_WCSRTOMBS)|g' \
	      -e 's|@''HAVE_WCSNRTOMBS''@|$(HAVE_WCSNRTOMBS)|g' \
	      -e 's|@''HAVE_WMEMCHR''@|$(HAVE_WMEMCHR)|g' \
	      -e 's|@''HAVE_WMEMCMP''@|$(HAVE_WMEMCMP)|g' \
	      -e 's|@''HAVE_WMEMCPY''@|$(HAVE_WMEMCPY)|g' \
	      -e 's|@''HAVE_WMEMMOVE''@|$(HAVE_WMEMMOVE)|g' \
	      -e 's|@''HAVE_WMEMSET''@|$(HAVE_WMEMSET)|g' \
	      -e 's|@''HAVE_WCSLEN''@|$(HAVE_WCSLEN)|g' \
	      -e 's|@''HAVE_WCSNLEN''@|$(HAVE_WCSNLEN)|g' \
	      -e 's|@''HAVE_WCSCPY''@|$(HAVE_WCSCPY)|g' \
	      -e 's|@''HAVE_WCPCPY''@|$(HAVE_WCPCPY)|g' \
	      -e 's|@''HAVE_WCSNCPY''@|$(HAVE_WCSNCPY)|g' \
	      -e 's|@''HAVE_WCPNCPY''@|$(HAVE_WCPNCPY)|g' \
	      -e 's|@''HAVE_WCSCAT''@|$(HAVE_WCSCAT)|g' \
	      -e 's|@''HAVE_WCSNCAT''@|$(HAVE_WCSNCAT)|g' \
	      -e 's|@''HAVE_WCSCMP''@|$(HAVE_WCSCMP)|g' \
	      -e 's|@''HAVE_WCSNCMP''@|$(HAVE_WCSNCMP)|g' \
	      -e 's|@''HAVE_WCSCASECMP''@|$(HAVE_WCSCASECMP)|g' \
	      -e 's|@''HAVE_WCSNCASECMP''@|$(HAVE_WCSNCASECMP)|g' \
	      -e 's|@''HAVE_WCSCOLL''@|$(HAVE_WCSCOLL)|g' \
	      -e 's|@''HAVE_WCSXFRM''@|$(HAVE_WCSXFRM)|g' \
	      -e 's|@''HAVE_WCSDUP''@|$(HAVE_WCSDUP)|g' \
	      -e 's|@''HAVE_WCSCHR''@|$(HAVE_WCSCHR)|g' \
	      -e 's|@''HAVE_WCSRCHR''@|$(HAVE_WCSRCHR)|g' \
	      -e 's|@''HAVE_WCSCSPN''@|$(HAVE_WCSCSPN)|g' \
	      -e 's|@''HAVE_WCSSPN''@|$(HAVE_WCSSPN)|g' \
	      -e 's|@''HAVE_WCSPBRK''@|$(HAVE_WCSPBRK)|g' \
	      -e 's|@''HAVE_WCSSTR''@|$(HAVE_WCSSTR)|g' \
	      -e 's|@''HAVE_WCSTOK''@|$(HAVE_WCSTOK)|g' \
	      -e 's|@''HAVE_WCSWIDTH''@|$(HAVE_WCSWIDTH)|g' \
	      -e 's|@''HAVE_DECL_WCTOB''@|$(HAVE_DECL_WCTOB)|g' \
	      -e 's|@''HAVE_DECL_WCWIDTH''@|$(HAVE_DECL_WCWIDTH)|g' \
	  | \
	  sed -e 's|@''REPLACE_MBSTATE_T''@|$(REPLACE_MBSTATE_T)|g' \
	      -e 's|@''REPLACE_BTOWC''@|$(REPLACE_BTOWC)|g' \
	      -e 's|@''REPLACE_WCTOB''@|$(REPLACE_WCTOB)|g' \
	      -e 's|@''REPLACE_MBSINIT''@|$(REPLACE_MBSINIT)|g' \
	      -e 's|@''REPLACE_MBRTOWC''@|$(REPLACE_MBRTOWC)|g' \
	      -e 's|@''REPLACE_MBRLEN''@|$(REPLACE_MBRLEN)|g' \
	      -e 's|@''REPLACE_MBSRTOWCS''@|$(REPLACE_MBSRTOWCS)|g' \
	      -e 's|@''REPLACE_MBSNRTOWCS''@|$(REPLACE_MBSNRTOWCS)|g' \
	      -e 's|@''REPLACE_WCRTOMB''@|$(REPLACE_WCRTOMB)|g' \
	      -e 's|@''REPLACE_WCSRTOMBS''@|$(REPLACE_WCSRTOMBS)|g' \
	      -e 's|@''REPLACE_WCSNRTOMBS''@|$(REPLACE_WCSNRTOMBS)|g' \
	      -e 's|@''REPLACE_WCWIDTH''@|$(REPLACE_WCWIDTH)|g' \
	      -e 's|@''REPLACE_WCSWIDTH''@|$(REPLACE_WCSWIDTH)|g' \
	      -e '/definitions of _GL_FUNCDECL_RPL/r $(CXXDEFS_H)' \
	      -e '/definition of _GL_ARG_NONNULL/r $(ARG_NONNULL_H)' \
	      -e '/definition of _GL_WARN_ON_USE/r $(WARN_ON_USE_H)'; \
	} > $@-t && \
	mv $@-t $@
MOSTLYCLEANFILES += wchar.h wchar.h-t

EXTRA_DIST += wchar.in.h

## end   gnulib module wchar

## begin gnulib module wchar-tests

TESTS += test-wchar
check_PROGRAMS += test-wchar
EXTRA_DIST += test-wchar.c

## end   gnulib module wchar-tests

## begin gnulib module xsize

libtests_a_SOURCES += xsize.h xsize.c

## end   gnulib module xsize

# Clean up after Solaris cc.
clean-local:
	rm -rf SunWS_cache

mostlyclean-local: mostlyclean-generic
	@for dir in '' $(MOSTLYCLEANDIRS); do \
	  if test -n "$$dir" && test -d $$dir; then \
	    echo "rmdir $$dir"; rmdir $$dir; \
	  fi; \
	done; \
	:
