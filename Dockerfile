FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go main_test.go ./
COPY internal ./internal
RUN go test ./... && CGO_ENABLED=0 go build -trimpath -o /out/maintenance-poc .

FROM scratch
COPY --from=build /out/maintenance-poc /maintenance-poc
USER 65532:65532
ENV MCP_ADDR=0.0.0.0:8765
EXPOSE 8765
ENTRYPOINT ["/maintenance-poc", "--http"]
