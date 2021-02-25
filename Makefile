# This file is purely assistant to the project creator to build the program
# The Makefile script is based on CMake. Despite this, feel free to use it and modify for your own use
#
BUILD_DIR=build
EXE=wasmisnotasm
DEBUGGER=kdbg

all: compile

compile:
	make -C $(BUILD_DIR)

run: compile
	$(BUILD_DIR)/$(EXE)

debug: compile
	$(DEBUGGER) $(BUILD_DIR)/$(EXE)

gen: clean
	mkdir $(BUILD_DIR) && cd $(BUILD_DIR) && cmake .. && cd ..

clean:
	rm -rf $(BUILD_DIR)

