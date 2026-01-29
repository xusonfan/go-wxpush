FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o wxpush main.go

FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app
COPY --from=builder /app/wxpush .

EXPOSE 5566

ENTRYPOINT ["./wxpush"]
CMD ["-port", "5566"]