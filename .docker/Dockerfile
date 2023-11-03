FROM golang:1.21.3-alpine3.18 as builder

ENV GOPRIVATE=github.com

RUN   apk update && \
      apk add --no-cache \
      curl \
      build-base \
      git \
      bash \
      openssh-client \
      openssh-keygen

WORKDIR /pow

COPY . .

RUN GO111MODULE=on go mod tidy
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o pow main.go

FROM alpine:3.18.4
RUN apk add --no-cache tzdata
RUN cp /usr/share/zoneinfo/Etc/UTC /etc/localtime
RUN echo "Etc/UTC" >  /etc/timezone

RUN mkdir -p /pow
WORKDIR /pow

COPY --from=builder /pow .

