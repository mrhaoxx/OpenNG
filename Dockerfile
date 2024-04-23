FROM golang:1-bookworm AS build

RUN apt-get update && apt-get install -y build-essential git

COPY . /go/src/github.com/mrhaoxx/OpenNG

RUN cd /go/src/github.com/mrhaoxx/OpenNG && ./build.sh -o /NetGATE

FROM debian:bookworm AS runtime

# RUN apk add tzdata ca-certificates libc6-compat libgcc libstdc++

COPY --from=build /NetGATE /NetGATE

ENTRYPOINT ["/NetGATE"]
