FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -o /out/proxy .

FROM alpine:3.21
COPY --from=build /out/proxy /usr/local/bin/proxy
EXPOSE 80
ENTRYPOINT ["/usr/local/bin/proxy"]
