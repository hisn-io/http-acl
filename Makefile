CARGO_BIN ?= $(shell which cargo)

.PHONY: publish publish-http-acl publish-http-acl-reqwest publish-http-acl-wasmtime

# http-acl must be published first, since the other two depend on it. If
# publish-http-acl-reqwest or publish-http-acl-wasmtime fails because crates.io hasn't finished indexing
# the new http-acl version yet, wait a few seconds and re-run it on its own.
publish: publish-http-acl publish-http-acl-reqwest publish-http-acl-wasmtime

publish-http-acl:
	cd http-acl && $(CARGO_BIN) publish

publish-http-acl-reqwest:
	cd http-acl-reqwest && $(CARGO_BIN) publish

publish-http-acl-wasmtime:
	cd http-acl-wasmtime && $(CARGO_BIN) publish
