FROM golang:bookworm AS build

RUN apt-get update && apt-get install -y build-essential git

COPY . /go/src/github.com/mrhaoxx/OpenNG

RUN cd /go/src/github.com/mrhaoxx/OpenNG && ./build.sh -o /NetGATE

FROM debian:bookworm AS runtime

COPY --from=build /NetGATE /NetGATE

ENTRYPOINT ["/NetGATE"]
