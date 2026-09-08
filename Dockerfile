# API-only service. The UI moved out to construct-space/delivery and is
# deployed separately at https://delivery.lisaos.dev; Oracle + my/ consume the
# same /api/* surface via their own gateways.

FROM docker.io/library/golang:1.26-alpine AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o delivery .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=build /app/delivery .
EXPOSE 8005 587
CMD ["./delivery"]
