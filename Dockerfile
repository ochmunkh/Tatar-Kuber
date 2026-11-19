# TATAR-Kuber slim image (multi-stage, эх кодоос).
#   docker build -t tatar-kuber .
#   docker run --rm -v "$PWD:/work" -w /work tatar-kuber scan --raw-dir ./raw --out-dir .
# Тэмдэглэл: энэ образ нь orchestrator (tatar-kuber)-ийг л агуулна. Live scan-д
# scanner CLI-ууд (trivy, kubescape, ...) тусад нь шаардлагатай; offline ingest,
# report, gate нь энэ образ дотор бүрэн ажиллана (registry шигтгэгдсэн).
FROM golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/tatar-kuber ./cmd/tatar-kuber

FROM gcr.io/distroless/static:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931
COPY --from=build /out/tatar-kuber /usr/local/bin/tatar-kuber
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/tatar-kuber"]
