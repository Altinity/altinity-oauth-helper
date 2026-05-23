# ch-jwt-verify sidecar image. Built by scripts/build-image.sh: cross-compile
# a statically-linked binary into the build context, then docker build with
# legacy DOCKER_BUILDKIT=0 (some sandboxed docker proxies refuse the
# privileged container buildkit needs for cross-arch).
FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /bin/
COPY ch-jwt-verify .

EXPOSE 9999

ENTRYPOINT ["/bin/ch-jwt-verify"]
