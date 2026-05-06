FROM quay.io/keycloak/keycloak:26.0

COPY realm-export.json /opt/keycloak/data/import/realm-export.json

ENV KC_HEALTH_ENABLED=true \
    KC_METRICS_ENABLED=false \
    KC_HTTP_ENABLED=true \
    KC_HOSTNAME_STRICT=false \
    KC_PROXY_HEADERS=xforwarded \
    KC_DB=dev-mem \
    KC_BOOTSTRAP_ADMIN_USERNAME=admin \
    KC_BOOTSTRAP_ADMIN_PASSWORD=admin

EXPOSE 8080

ENTRYPOINT ["/opt/keycloak/bin/kc.sh", "start", "--import-realm", "--optimized=false"]
