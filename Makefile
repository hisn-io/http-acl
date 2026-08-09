CARGO_BIN ?= $(shell which cargo)

.PHONY: publish publish-http-acl publish-http-acl-reqwest

# http-acl must be published first, since http-acl-reqwest depends on it. If
# publish-http-acl-reqwest fails because crates.io hasn't finished indexing
# the new http-acl version yet, wait a few seconds and re-run it on its own.
publish: publish-http-acl publish-http-acl-reqwest

publish-http-acl:
	cd http-acl && $(CARGO_BIN) publish

publish-http-acl-reqwest:
	cd http-acl-reqwest && $(CARGO_BIN) publish
