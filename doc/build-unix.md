# UNIX BUILD NOTES

Some notes on how to build Bitcoin Core in Unix.

(For BSD specific instructions, see `build-*bsd.md` in this directory.)

## To Build

```bash
cmake -B build
```
Run `cmake -B build -LH` to see the full list of available options.

```bash
cmake --build build    # Append "-j N" for N parallel jobs
cmake --install build  # Optional
```

See below for instructions on how to [install the dependencies on popular Linux
distributions](#dependencies).

## Memory Requirements

C++ compilers are memory-hungry. It is recommended to have at least 1.5 GB of
memory available when compiling Bitcoin Core. On systems with less, gcc can be
tuned to conserve memory with additional `CMAKE_CXX_FLAGS`:


    cmake -B build -DCMAKE_CXX_FLAGS="--param ggc-min-expand=1 --param ggc-min-heapsize=32768"

Alternatively, or in addition, debugging information can be skipped for compilation.
For the default build type `RelWithDebInfo`, the default compile flags are
`-O2 -g`, and can be changed with:

    cmake -B build -DCMAKE_CXX_FLAGS_RELWITHDEBINFO="-O2 -g0"

Finally, clang (often less resource hungry) can be used instead of gcc, which is used by default:

    cmake -B build -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_C_COMPILER=clang

## Dependencies

You can either build from self-compiled [depends](/depends/README.md) or
install the dependencies from your distribution package manager. Dependencies
for additional features in later columns are optional.

| Package manager         | Required build dependencies | SQLite (wallet) | Cap'n Proto (IPC) | ZMQ | USDT | Qt and libqrencode (GUI) |
| ----------------------- | --------------------------- | --------------- | ----------------- | --- | ---- | ------------------------ |
| Debian / Ubuntu (`apt`) | `build-essential cmake pkgconf python3 libevent-dev libboost-dev` | `libsqlite3-dev` | `libcapnp-dev capnproto` | `libzmq3-dev` | `systemtap-sdt-dev` | `qt6-base-dev qt6-tools-dev qt6-l10n-tools qt6-tools-dev-tools libgl-dev qt6-wayland libqrencode-dev` |
| Fedora (`dnf`)          | `gcc-c++ cmake make python3 libevent-devel boost-devel` | `sqlite-devel` | `capnproto capnproto-devel` | `zeromq-devel` | `systemtap-sdt-devel` | `qt6-qtbase-devel qt6-qttools-devel qt6-qtwayland qrencode-devel` |
| Alpine (`apk`)          | `build-base cmake linux-headers pkgconf python3 libevent-dev boost-dev` | `sqlite-dev` | `capnproto capnproto-dev` | `zeromq-dev` | Not supported | `qt6-qtbase-dev qt6-qttools-dev libqrencode-dev` |
| Arch (`pacman`)         | `gcc make cmake pkgconf python libevent boost` | `sqlite` | `capnproto` | `zeromq` | `systemtap` | `qt6-base qt6-tools qt6-wayland qrencode` |

For Debian "oldstable", or earlier Ubuntu LTS releases, you may need to pick a
later compiler version, according to the [dependencies](/doc/dependencies.md)
documentation.

Now, you can either build from self-compiled [depends](#dependencies) or install the required dependencies:

    sudo apt-get install libboost-dev libcapnp-dev capnproto

User-Space, Statically Defined Tracing (USDT) dependencies:

    sudo apt install systemtap-sdt-dev


### Fedora

#### Dependency Build Instructions

Build requirements:

    sudo dnf install gcc-c++ cmake make python3

Now, you can either build from self-compiled [depends](#dependencies) or install the required dependencies:

    sudo dnf install boost-devel capnproto capnproto-devel

User-Space, Statically Defined Tracing (USDT) dependencies:

    sudo dnf install systemtap-sdt-devel


### Alpine

#### Dependency Build Instructions

Build requirements:

    apk add build-base cmake linux-headers pkgconf python3

Now, you can either build from self-compiled [depends](#dependencies) or install the required dependencies:

    apk add boost-dev capnproto capnproto-dev

User-Space, Statically Defined Tracing (USDT) is not supported or tested on Alpine Linux at this time.

## Dependencies

See [dependencies.md](dependencies.md) for a complete overview, and
[depends](/depends/README.md) on how to compile them yourself, if you wish to
not use the packages of your Linux distribution.

Setup and Build Example: Arch Linux
-----------------------------------
This example lists the steps necessary to setup and build a command line only distribution of the latest changes on Arch Linux:

    pacman --sync --needed capnproto cmake boost gcc git make python
    git clone https://github.com/bitcoin/bitcoin.git
    cd bitcoin/
    cmake -B build
    cmake --build build
    ctest --test-dir build
    ./build/bin/bitcoind
    ./build/bin/bitcoin help

