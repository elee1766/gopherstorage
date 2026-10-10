FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /gopherstorage ./cmd/gopherstorage

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /gopherstorage /gopherstorage
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/gopherstorage", "-config", "/config/config.yaml"]
