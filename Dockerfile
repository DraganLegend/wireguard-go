FROM golang:1.20 as builder
WORKDIR /src
COPY . .
RUN ./build.sh

FROM alpine:latest
RUN apk add --no-cache iptables iproute2 wireguard-tools
COPY --from=builder /src/wireguard-go /usr/local/bin/wireguard-go
ENTRYPOINT ["/usr/local/bin/wireguard-go"]
CMD ["wg0"]
