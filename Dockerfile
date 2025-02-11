FROM golang:1.22-alpine as build

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN GOOS=linux go build -o .bin/app

FROM alpine:latest as runtime

WORKDIR /app

COPY --from=build /app/.bin/app ./.bin/app

CMD ["./.bin/app"]