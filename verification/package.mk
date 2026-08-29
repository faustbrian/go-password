.PHONY: api-docs boundaries interoperability kubernetes-bench portability resource

api-docs:
	go run ./verification/check-api-docs.go

boundaries:
	./verification/check-boundaries.sh

interoperability:
	./verification/check-interoperability.sh

kubernetes-bench:
	./verification/check-kubernetes-benchmarks.sh

portability:
	./verification/check-portability.sh

resource:
	go test -race -tags=resource -run '^TestDefaultPolicyResourceAdmissionStress$$' ./
