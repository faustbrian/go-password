.PHONY: api-docs boundaries conformance interoperability kubernetes-bench portability resource

api-docs:
	go run ./verification/check-api-docs.go

boundaries:
	./verification/check-boundaries.sh

conformance:
	./verification/check-conformance.sh

interoperability:
	./verification/check-interoperability.sh

kubernetes-bench:
	./verification/check-kubernetes-benchmarks.sh

portability:
	./verification/check-portability.sh

resource:
	go test -race -tags=resource -run '^TestDefaultPolicyResourceAdmissionStress$$' ./
