FROM quay.io/keycloak/keycloak:26.0

COPY realm-export.json /opt/keycloak/data/import/realm-export.json

ENV KC_HEALTH_ENABLED=true \
    KC_METRICS_ENABLED=false \
    KC_HOSTNAME_STRICT=false \
    KC_PROXY_HEADERS=xforwarded

# Bootstrap admin credentials MUST be supplied at runtime via:
#   KC_BOOTSTRAP_ADMIN_USERNAME
#   KC_BOOTSTRAP_ADMIN_PASSWORD
# Never bake them into the image — this image is published publicly to GHCR.

EXPOSE 8080

# start-dev is correct for this throwaway demo IdP:
#   - in-memory H2 DB (resets between deploys, ideal for live re-runs of the demo)
#   - HTTP enabled by default (TLS is terminated upstream by MC + the PZ)
#   - relaxed hostname rules (accepts whatever PZ/MC URL fronts it)
#   - no JGroups clustering (local-cache only)
ENTRYPOINT ["/opt/keycloak/bin/kc.sh", "start-dev", "--import-realm"]
