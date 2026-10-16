FROM alpine:3.22
ARG FIXTURE=legitimate
RUN printf '%s\n' "$FIXTURE" > /fixture.txt
USER 65534:65534
CMD ["/bin/sh", "-c", "cat /fixture.txt; sleep 3600"]
