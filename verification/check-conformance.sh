#!/usr/bin/env bash
set -euo pipefail

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
GOWORK=off go test ./ -run \
	'^(TestMaintainedImplementationVectors|TestEncodedHashParserMatrix|TestBcryptParserRejectsNonCanonicalBase64|TestArgon2idHashVerifyAndUpgrade|TestLaravelBcryptUpgrade|TestNeedsRehashNeverRecommendsDowngrade|TestNeedsRehashArgon2idTransitionMatrix|TestHostileHashesAreRejectedBeforePrimitive)$' \
	-count=1
GOWORK=off go test ./passwordauth -run \
	'^(TestAuthenticateReturnsExplicitCASUpgrade|TestConcurrentUpgradeCrashAndCASStatesPreserveUsableHash)$' \
	-count=1
./verification/check-interoperability.sh
