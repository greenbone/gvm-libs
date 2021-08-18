INSTALLATION INSTRUCTIONS FOR GVM-LIBS
======================================

Please note: The reference system used by most of the developers is Debian
GNU/Linux 'Buster' 10. The build might fail on any other system. Also, it is
necessary to install dependent development packages.

Prerequisites for gvm-libs
--------------------------

See at the end of this section how to easily install these prerequisites on
some supported platforms.

General build environment:
* a C compiler (e.g. gcc)
* cmake >= 3.0
* pkg-config

Specific development libraries:
* libglib >= 2.42 (all)
* libgio >= 2.42 (util)
* zlib >= 1.2.8 (util)
* libgpgme >= 1.7.0 (util)
* libgnutls >= 3.2.15 (util)
* libuuid >= 2.25.0 (util)
* libssh >= 0.6.0 (util)
* libhiredis >= 0.10.1 (util)
* libxml2 >= 2.0 (util)
* libnet1 >= 1.1.2.1 (boreas)
* libpcap
* libgcrypt

Prerequisites for building documentation:
* doxygen
* xmltoman (optional, for building man page)

Prerequisites for building tests:
* [Cgreen](https://cgreen-devs.github.io/#_installing_cgreen) (optional, for building tests)

Install prerequisites on Debian GNU/Linux 'Buster' 10:

    apt-get install \
    cmake \
    pkg-config \
    libglib2.0-dev \
    libgpgme-dev \
    libgnutls28-dev \
    uuid-dev \
    libssh-gcrypt-dev \
    libhiredis-dev \
    libxml2-dev \
    libpcap-dev \
    libnet1-dev


Prerequisites for Optional Features
-----------------------------------

Certain features of gvm-libs are optional and require the following:

Prerequisites for LDAP authentication:
* libldap2 library >= 2.4.44 (util) (Debian package: libldap2-dev)

Prerequisites for RADIUS authentication:
* libradcli4 library >= 1.2.6 (util) (Debian package: libradcli-dev)
* Alternative: libfreeradius3 library (util) (Debian package: libfreeradius-dev)

Install prerequisites for optional features on Debian GNU/Linux 'Buster' 10:

    apt-get install \
    libldap2-dev \
    libradcli-dev


Compiling gvm-libs
------------------

If you have installed required libraries to a non-standard location, remember to
set the `PKG_CONFIG_PATH` environment variable to the location of your pkg-config
files before configuring:

    export PKG_CONFIG_PATH=/your/location/lib/pkgconfig:$PKG_CONFIG_PATH

Create a build directory and change working directory into it with

        mkdir build && cd build

Afterwards you can run `cmake` with different options:
* Configure `gvm-libs` build with a custom installation path:

        cmake -DCMAKE_INSTALL_PREFIX=/path/to/your/installation ..

* or (if you want to use the default installation path `/usr/local`):

        cmake ..

* Configure `gvm-libs` build with tests, you need to run `cmake` with `BUILD_TESTS`:

        cmake -DBUILD_TESTS=ON ..

The `cmake` command only needs to be executed once. Further information regarding cmake can be found [here](https://cmake.org/cmake/help/latest/manual/cmake.1.html#) or with the command `cmake --help-full`.
You can list all project options and settable variables with `cmake -LA`.

Thereafter, you need to compile and install the project with `make`.
The following command options are available:

    make                # build the libraries
    make help           # list possible make commands
    make doc            # build the documentation
    make doc-full       # build more developer-oriented documentation
    make tests          # build tests (requires BUILD_TESTS activated)
    make install        # install the build
    make rebuild_cache  # rebuild the cmake cache
    make format         # code style and formatting

Please note that you may have to execute `make install` as root, especially if
you have specified a prefix for which your user does not have full permissions.

You can also install specific components with make. See `make help` for more details.
You can remove the compiled binaries with `make clean`.

To clean up the full build environment, simply remove the contents of the `build`
directory you created above.

    cd .. && rm -rf build


Configurable Options
--------------------

During compilation, the build process uses a set of compiler options which
enable very strict error checking and asks the compiler to abort should it detect
any errors in the code. This is to ensure a maximum of code quality and
security.

Some (especially newer) compilers can be stricter than others when it comes
to error checking. While this is a good thing and the developers aim to address
all compiler warnings, it may lead the build process to abort on your system.

Should you notice error messages causing your build process to abort, do not
hesitate to contact the developers using the [Greenbone Community
Portal](https://community.greenbone.net/c/gse). Don't forget to include the
name and version of your compiler and distribution in your message.


Building GVM Libraries statically linked
----------------------------------------

If you want to build a statically linked version -- for example to subsequently
build a statically linked program using this library -- you need statically
linked versions of the prerequisite libraries as well.

This can be a problem with current versions of the GnuTLS library. In most
distributions GnuTLS is built with `p11-kit` support, which makes linking
statically against the GnuTLS library impossible. To work around this, you can
build the GnuTLS yourself after configuring it without support for `p11-kit`. This
can be done with the following parameters:

    ./configure --disable-shared --enable-static --without-p11-kit

Note that you will most likely want to add additional parameters to configure
the GnuTLS library based on your distributions policy and/or your personal
needs, e.g. the correct prefix so the statically linked version will be found.
The `make install` command will then build the GnuTLS library and install it
into the path you configured.

Once you have built and installed the GnuTLS library, configure this module
with the following parameters to request statically linked versions of
the single library modules:

    cmake -DBUILD_STATIC=1 -DBUILD_SHARED=0 ..

Once again, the `make install` command will build and install the requested
modules.
