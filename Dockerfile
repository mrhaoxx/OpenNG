FROM node:latest AS web

COPY ./ui/html /workdir

RUN cd /workdir/ && npm install && npm run build

FROM golang:bookworm AS build

RUN apt-get update && apt-get install -y build-essential git

COPY . /go/src/github.com/mrhaoxx/OpenNG
COPY --from=web /workdir/dist /go/src/github.com/mrhaoxx/OpenNG/ui/html/dist

RUN cd /go/src/github.com/mrhaoxx/OpenNG && ./build.sh -o /NetGATE

FROM debian:bookworm AS runtime

RUN apt-get update && apt-get install -y ca-certificates && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY --from=build /NetGATE /NetGATE


ENTRYPOINT ["/NetGATE"]
