# TATAR-Kuber slim image (multi-stage, эх кодоос).
#   docker build -t tatar-kuber .
#   docker run --rm -v "$PWD:/work" -w /work tatar-kuber scan --raw-dir ./raw -o .
# Тэмдэглэл: энэ образ нь orchestrator (tatar-kuber)-ийг л агуулна. Live scan-д
# scanner CLI-ууд (trivy, kubescape, ...) тусад нь шаардлагатай; offline ingest,
# report, gate нь энэ образ дотор бүрэн ажиллана (registry шигтгэгдсэн).
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download || true
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/tatar-kuber ./cmd/tatar-kuber

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/tatar-kuber /usr/local/bin/tatar-kuber
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/tatar-kuber"]
