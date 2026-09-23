FROM golang:1.24-alpine AS build
RUN apk add --no-cache build-base git
WORKDIR /src
COPY source/ ./
# Keep the edition and web assets of the verified deployment. CGO is required by SQLite.
RUN CGO_ENABLED=1 go build -tags timetzdata -o /tmp/signoz \
    -ldflags "-linkmode external -extldflags '-static' -s -w -X github.com/SigNoz/signoz/pkg/version.variant=enterprise -X github.com/SigNoz/signoz/pkg/version.version=v0.97.1-audit.1 -X github.com/SigNoz/signoz/pkg/version.hash=416e8d2a5eb1278666b9e67a4cddcbaead61bdc5" ./cmd/enterprise
FROM signoz/signoz:v0.97.1
COPY --from=build /tmp/signoz /root/signoz
