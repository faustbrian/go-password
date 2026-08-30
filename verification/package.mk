.PHONY: benchmark boundaries docs interoperability kubernetes-benchmark portability resource

benchmark:
	./scripts/check-benchmarks.sh

boundaries:
	./scripts/check-boundaries.sh

docs:
	./scripts/check-docs.sh

interoperability:
	./scripts/check-interoperability.sh

kubernetes-benchmark:
	./scripts/check-kubernetes-benchmarks.sh

portability:
	./scripts/check-portability.sh

resource:
	go test -race -tags=resource -run '^TestDefaultPolicyResourceAdmissionStress$$' ./
