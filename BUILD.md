# Building the Subspace project

## Install the required tools

1. Install [CMake](https://cmake.org/install/)
    * Don't use the one that comes with Visual Studio on Windows.
1. Install [Ninja](https://ninja-build.org/)
1. Install a version of libstdc++ of at least 12. This can be done on Ubuntu with `sudo apt install libstdc++-12-dev`

## Fetch submodule dependencies

From the root of the Subspace project, run:
```
git submodule update --init
```

## Configure the Subspace build

### Linux and Mac

On Linux and Mac, there is a shell script [`tools/configure.sh`](tools/configure.sh) that will run
`CMake` and configure it to build into the `out/` directory. The script can be
controlled through environment variables. By default it configures unit tests to be built.

```
# Release
./tools/configure.sh

# Debug
USE_DEBUG=true ./tools/configure.sh
```

If you want to build Subdoc, you will need [a recent LLVM installation](
#build-llvm). Then point the Subspace build to it and enable Subdoc through
environment variables.

```
LLVM_ROOT=/path/to/llvm/install USE_LLVM_CLANG=true SUBDOC=true ./tools/configure.sh
```

### Windows

Run CMake to configure the build to happen in the `out/` directory.
```
cmake -B out \
    -DSUBSPACE_BUILD_TESTS=ON \
    -BCMAKE_BUILD_TYPE=Release
```
Or for debug:
```
cmake -B out \
    -DSUBSPACE_BUILD_TESTS=ON \
    -BCMAKE_BUILD_TYPE=Debug
```

If you want to build Subdoc, you will need [a recent LLVM installation](
#build-llvm). Then point the build to it and enable Subdoc with the
`SUBSPACE_BUILD_SUBDOC` cmake variable.

Due to Windows CRT limitations, you will need to use the same build type
(Release vs Debug) for Subdoc as was used for LLVM, which probably means
"RelWithDebInfo" or "Release".

```
set LLVM_DIR=/path/to/llvm/install/lib/cmake/llvm
set Clang_DIR=/path/to/llvm/install/lib/cmake/clang
cmake -B out \
    -DSUBSPACE_BUILD_TESTS=ON \
    -DSUBSPACE_BUILD_SUBDOC=ON \
    -BCMAKE_BUILD_TYPE=RelWithDebInfo
```

## Build Subspace

Once the build is configured, use Cmake to build and run tests. See
`cmake --help` for more options to these.

To build (with some parallelism):
```
cmake --build out -j 20
```
To run tests:
```
ctest --test-dir out -j 10
```

## Build LLVM

To build Subdoc you will need a recent LLVM installation, and to build Subspace
you may need a newer C++ compiler than is available on your system. You can
install prebuilt versions of these, or you can build them yourself.

To get a prebuilt version of LLVM, you can do the following:
```
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh ${clang_version} all
```

If you are building LLVM yourself, you can use the following to configure,
build, and install it:
```
cmake -S llvm -B out -G Ninja \
    -DLLVM_ENABLE_PROJECTS="clang;lld;clang-tools-extra;compiler-rt" \
    -DCMAKE_INSTALL_PREFIX=install \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DLLVM_ENABLE_ASSERTIONS=ON
cmake --build out
cmake --install out
```

For `LLVM_ENABLE_PROJECTS`, the following may be wanted or not. They each add
more time to the LLVM build.
* `clang-tools-extra`: builds clang-format and clangd for you to use.
* `lld`: builds the lld linker which you can optionally use.
* `compiler-rt`: builds the sanitizers for using in Subspace unittests.
