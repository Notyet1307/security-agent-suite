# syntax=docker/dockerfile:1.7
FROM golang:1.27.1-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/sasd ./cmd/sasd &&     CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/sasctl ./cmd/sasctl

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/sasd /usr/local/bin/sasd
COPY --from=build /out/sasctl /usr/local/bin/sasctl
COPY configs /app/configs
COPY agents /app/agents
COPY contracts /app/contracts
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/sasd"]
