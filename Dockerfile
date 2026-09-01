# ch-jwt-verify sidecar image. Built by scripts/build-image.sh: cross-compile
# a statically-linked binary into the build context, then docker build with
# legacy DOCKER_BUILDKIT=0 (some sandboxed docker proxies refuse the
# privileged container buildkit needs for cross-arch).
# Pin to an Alpine minor release so a rebuild cannot silently switch major or
# minor runtime bases. Publication scripts pull this exact tag per architecture.
FROM alpine:3.24

RUN apk --no-cache add ca-certificates

WORKDIR /bin/
COPY ch-jwt-verify .

EXPOSE 9999

ENTRYPOINT ["/bin/ch-jwt-verify"]
