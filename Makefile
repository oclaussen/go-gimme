all: configfiles ssl

.PHONY: configfiles
configfiles:
	$(MAKE) -C configfiles

.PHONY: ssl
ssl:
	$(MAKE) -C ssl
