# TATAR-Kuber slim image (multi-stage, эх кодоос).
#   docker build -t tatar-kuber .
#   docker run --rm -v "$PWD:/work" -w /work tatar-kuber scan --raw-dir ./raw --out-dir .
# Тэмдэглэл: энэ образ нь orchestrator (tatar-kuber)-ийг л агуулна. Live scan-д
# scanner CLI-ууд (trivy, kubescape, ...) тусад нь шаардлагатай; offline ingest,
# report, gate нь энэ образ дотор бүрэн ажиллана (registry шигтгэгдсэн).
FROM golang:1.25-alpine@sha256:1ae0735f00daffa3aaf1363a5184c0d2dc55c78e3db4ec70241cdac97bf84b59 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/tatar-kuber ./cmd/tatar-kuber

FROM gcr.io/distroless/static:nonroot@sha256:8ce6dd87e9823c5b48dcfb2c8604714ccb351ce59607327bcc4957448da279b5
COPY --from=build /out/tatar-kuber /usr/local/bin/tatar-kuber
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/tatar-kuber"]
