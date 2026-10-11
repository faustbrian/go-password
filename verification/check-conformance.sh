#!/usr/bin/env bash
set -euo pipefail

local_only=false
if [[ $# -gt 1 || ( $# -eq 1 && "${1:-}" != --local ) ]]; then
	printf 'usage: %s [--local]\n' "$0" >&2
	exit 2
fi
if [[ $# -eq 1 ]]; then
	local_only=true
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="${root}/specification/manifest.tsv"
register="${root}/docs/specification-decisions.md"
expected_header=$'id\tversion\trole\tstatus\tsha256\tbytes\turl'

[[ -f "${manifest}" && -f "${register}" ]] || {
	printf 'missing password specification evidence\n' >&2
	exit 1
}
[[ "$(head -n 1 "${manifest}")" == "${expected_header}" ]] || {
	printf 'invalid password specification manifest header\n' >&2
	exit 1
}
[[ "$(grep -Ec '^## PASSWORD-DEC-[0-9]{3}:' "${register}")" -eq 7 ]] || {
	printf 'password decision register must contain 7 decisions\n' >&2
	exit 1
}

cd "${root}"
if [[ "${local_only}" == true ]]; then
	exit 0
fi

GOWORK=off go test ./ -run \
	'^(TestMaintainedImplementationVectors|TestEncodedHashParserMatrix|TestBcryptParserRejectsNonCanonicalBase64|TestArgon2idHashVerifyAndUpgrade|TestLaravelBcryptUpgrade|TestNeedsRehashNeverRecommendsDowngrade|TestNeedsRehashArgon2idTransitionMatrix|TestHostileHashesAreRejectedBeforePrimitive)$' \
	-count=1
GOWORK=off go test ./passwordauth -run \
	'^(TestAuthenticateReturnsExplicitCASUpgrade|TestConcurrentUpgradeCrashAndCASStatesPreserveUsableHash)$' \
	-count=1
./verification/check-interoperability.sh
