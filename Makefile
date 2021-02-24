BUILD_DIR=build
EXE=wasmisnotasm
DEBUGGER=kdbg

all: $(BUILD_DIR)/$(EXE)

$(BUILD_DIR)/$(EXE):
	make -C $(BUILD_DIR)

run: $(BUILD_DIR)/$(EXE)
	$(BUILD_DIR)/$(EXE)

debug: build
	$(DEBUGGER) $(BUILD_DIR)/$(EXE)

gen: clean
	mkdir $(BUILD_DIR) && cd $(BUILD_DIR) && cmake .. && cd ..

clean:
	rm -rf $(BUILD_DIR)

