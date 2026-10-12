GOLIB ?= golib

.PHONY: source-docs-check check check-full ci cohesion inventory repository-check specification-check specification-check-online workflows boundaries conformance-local

check: source-docs-check boundaries conformance-local
	$(GOLIB) check --local --all

check-full: source-docs-check specification-check-online
	$(GOLIB) check --all

boundaries:
	sh verification/check-boundaries.sh

conformance-local:
	bash verification/check-conformance.sh --local

ci: source-docs-check repository-check cohesion specification-check workflows check

cohesion:
	$(GOLIB) cohesion check

inventory repository-check:
	$(GOLIB) repository check

specification-check:
	$(GOLIB) specification check

specification-check-online:
	$(GOLIB) specification check --online

workflows:
	$(GOLIB) workflows check

source-docs-check:
	$(GOLIB) source-docs check
