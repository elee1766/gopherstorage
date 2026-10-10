FROM golang:1.27-alpine@sha256:738d1cf061836894ff6bb8c33881080ac66de8cf0586615012a0c8f592649cfa AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY --from=remotestorage /go.mod /go.sum /remotestorage/
COPY --from=remotestorage /pkg /remotestorage/pkg
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /gopherstorage ./cmd/gopherstorage

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /gopherstorage /gopherstorage
VOLUME /var/lib/gopherstorage
EXPOSE 8080
ENTRYPOINT ["/gopherstorage", "-config", "/config/config.yaml"]
