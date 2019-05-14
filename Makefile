all: configfiles

.PHONY: configfiles
configfiles:
	$(MAKE) -C configfiles
