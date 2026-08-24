FROM scratch

COPY --chown=10001:10001 wiregate-web /wiregate-web
COPY --chown=10001:10001 rootfs/ /

USER 10001:10001
EXPOSE 8443
ENTRYPOINT ["/wiregate-web"]
CMD ["-config", "/etc/wiregate/web.yaml"]
