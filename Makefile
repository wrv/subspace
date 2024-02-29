RLBOX_ROOT=$(shell pwd)/third_party/rlbox_wasm2c_sandbox

#RLBOX headers
RLBOX_INCLUDE=$(RLBOX_ROOT)/build/_deps/rlbox-src/code/include

#Our Wasi-SDK
WASI_SDK_ROOT=$(RLBOX_ROOT)/build/_deps/wasiclang-src

#location of our wasi/wasm runtime
WASM2C_RUNTIME_PATH=$(RLBOX_ROOT)/build/_deps/mod_wasm2c-src/wasm2c
WASI_RUNTIME_FILES=$(addprefix $(WASM2C_RUNTIME_PATH), /wasm-rt-impl.c /wasm-rt-mem-impl.c)

#Some more wasi/wasm runtime files
WASM2C_RUNTIME_FILES=$(addprefix $(RLBOX_ROOT)/src, /wasm2c_rt_minwasi.c /wasm2c_rt_mem.c)

WASI_CLANG=$(WASI_SDK_ROOT)/bin/clang
WASI_SYSROOT=$(WASI_SDK_ROOT)/share/wasi-sysroot
WASM2C=$(RLBOX_ROOT)/build/_deps/mod_wasm2c-src/bin/wasm2c
WASM2C_FLAGS=-DWASM_RT_CORE_TYPES_DEFINED -Du8=uint8_t -Du16=uint16_t -Du32=uint32_t -Du64=uint64_t -Ds8=int8_t -Ds16=int16_t -Ds32=int32_t -Ds64=int64_t -Df32=float -Df64=double

#CFLAGS for compiling files to place nice with wasm2c
WASM_CFLAGS=-Wl,--export-all -Wl,--stack-first -Wl,-z,stack-size=262144 -Wl,--no-entry -Wl,--growable-table -Wl,--import-memory -Wl,--import-table

all: third_party/md4c/src/md4c.wasm third_party/md4c/src/md4c.wasm.c md4c.wasm.a

clean:
	cd third_party/md4c/src; rm -rf md4c.wasm md4c.wasm.c md4c.wasm.h *.o *.a

#Step 1: build our library into wasm, using clang from the wasi-sdk
third_party/md4c/src/md4c.wasm: third_party/md4c/src/md4c-html.c
	$(WASI_CLANG) --sysroot $(WASI_SYSROOT) $(WASM_CFLAGS) $(RLBOX_ROOT)/c_src/wasm2c_sandbox_wrapper.c third_party/md4c/src/md4c-html.c third_party/md4c/src/md4c.c third_party/md4c/src/entity.c -o third_party/md4c/src/md4c.wasm

#Step 2: use wasm2c to convert our wasm to a C implementation of wasm we can link with our app.
#    Sed the typedefs to not conflict with subspace types
third_party/md4c/src/md4c.wasm.c: third_party/md4c/src/md4c.wasm
	$(WASM2C) third_party/md4c/src/md4c.wasm -o third_party/md4c/src/md4c.wasm.c

#Step 3: compiling and linking our application with our library
md4c.wasm.a: third_party/md4c/src/md4c.wasm.c
	cd third_party/md4c/src/; $(CC) -c $(WASM2C_RUNTIME_FILES) $(WASI_RUNTIME_FILES) -I$(RLBOX_INCLUDE) -I$(RLBOX_ROOT)/include -I$(WASM2C_RUNTIME_PATH)
	cd third_party/md4c/src/; $(CC) -c -I$(RLBOX_INCLUDE) -I$(RLBOX_ROOT)/include -I$(WASM2C_RUNTIME_PATH) md4c.wasm.c $(WASM2C_FLAGS)
	cd third_party/md4c/src/; ar rcs $@ *.o