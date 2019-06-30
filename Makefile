all: configfiles ssl

.PHONY: configfiles
configfiles:
	$(MAKE) -C configfiles

.PHONY: ssh
ssh:
	$(MAKE) -C ssh

.PHONY: ssl
ssl:
	$(MAKE) -C ssl
