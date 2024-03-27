FROM golang:alpine AS build

RUN apk add build-base bash git coreutils

COPY . /go/src/github.com/mrhaoxx/OpenNG

RUN cd /go/src/github.com/mrhaoxx/OpenNG && ./build.sh -o /NetGATE

FROM alpine:latest AS runtime

COPY --from=build /NetGATE /NetGATE

ENTRYPOINT ["/NetGATE"]
