#!/bin/sh
set -eu

dependencies=$(go list -deps ./...)
for forbidden in \
	github.com/faustbrian/go-authentication \
	github.com/faustbrian/go-service \
	github.com/faustbrian/go-log \
	github.com/faustbrian/go-telemetry \
	github.com/faustbrian/go-postgres
do
	if printf '%s\n' "$dependencies" | grep -Eq "^${forbidden}(/|$)"; then
		printf 'forbidden reverse dependency: %s\n' "$forbidden" >&2
		exit 1
	fi
done

unsafe_imports=$(find . -type f -name '*.go' -not -name '*_test.go' \
	-not -path './.git/*' -exec grep -nE '(^|[[:space:]])"unsafe"|import "C"' {} + || true)
if [ -n "$unsafe_imports" ]; then
	printf '%s\n' 'unsafe or cgo is forbidden' >&2
	printf '%s\n' "$unsafe_imports" >&2
	exit 1
fi

if find . -type f -name '*.s' -not -path './.git/*' -print -quit | grep -q .; then
	printf '%s\n' 'custom assembly is forbidden' >&2
	exit 1
fi
