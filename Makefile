run: build
	@./run.sh
build:
	@$(MAKE) -C out
debug:
	kdbg out/wasmnotasm
cleanbuild:
	@./gen.sh
