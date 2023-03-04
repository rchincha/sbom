BINDIR=bin

.PHONY: binary
binary:
	mkdir -p ${BINDIR}
	go build -v -o ${BINDIR}/sbom ./cmd/sbom/...
