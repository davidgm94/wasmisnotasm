run: build
	@./run.sh
build:
	@$(MAKE) -C out
cleanbuild:
	@./gen.sh
