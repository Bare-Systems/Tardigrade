# Tardigrade Kubernetes Deployment

## Deployment topology

Tardigrade runs as a standard Kubernetes `Deployment` behind a `Service`. It does not yet implement Kubernetes Ingress controller semantics or Gateway API resources — it operates as a standalone reverse proxy pod rather than a Kubernetes-native control-plane component.

Recommended topology for most use cases:

```
Internet / LoadBalancer Service (type: LoadBalancer or NodePort)
    └── Tardigrade Deployment (ClusterIP Service)
            └── Backend Services (ClusterIP)
```

For cluster-internal use, omit the LoadBalancer and use a ClusterIP Service directly.

## Helm chart

```bash
# Install with Helm from source
helm install tardigrade ./deploy/kubernetes/helm/tardigrade \
  --namespace tardigrade --create-namespace \
  --set env.TARDIGRADE_UPSTREAM_BASE_URL=http://backend:8080

# Upgrade
helm upgrade tardigrade ./deploy/kubernetes/helm/tardigrade \
  --namespace tardigrade

# Uninstall
helm uninstall tardigrade --namespace tardigrade
```

### TLS

Mount a Kubernetes TLS Secret:

```bash
# Create the Secret from a cert/key pair
kubectl create secret tls tardigrade-tls \
  --cert=path/to/tls.crt --key=path/to/tls.key \
  --namespace tardigrade

# Install with TLS enabled
helm install tardigrade ./deploy/kubernetes/helm/tardigrade \
  --namespace tardigrade --create-namespace \
  --set tls.enabled=true \
  --set tls.secretName=tardigrade-tls \
  --set env.TARDIGRADE_UPSTREAM_BASE_URL=http://backend:8080
```

### Config file

Mount a config file from a ConfigMap:

```bash
kubectl create configmap tardigrade-config \
  --from-file=tardigrade.conf=./config/tardigrade.conf \
  --namespace tardigrade

helm install tardigrade ./deploy/kubernetes/helm/tardigrade \
  --namespace tardigrade --create-namespace \
  --set config.enabled=true \
  --set config.configMapName=tardigrade-config
```

### Secrets via Secret references

Use `envFrom` to pull env vars from a Kubernetes Secret:

```yaml
# values-prod.yaml
envFrom:
  - secretRef:
      name: tardigrade-secrets
```

The Secret should contain `TARDIGRADE_JWT_SECRET`, `TARDIGRADE_TRUST_SHARED_SECRET`, etc.

## Health probes

Tardigrade exposes `/health` on its listen port. Liveness and readiness probes are pre-configured in the Helm chart. Adjust `initialDelaySeconds` if your upstream needs extra warm-up time.

## Hot reload in Kubernetes

Tardigrade supports `SIGHUP`-based hot reload. In Kubernetes, trigger it with:

```bash
kubectl exec -n tardigrade deployment/tardigrade -- kill -HUP 1
```

Because the process runs as PID 1 inside the container, `kill -HUP 1` reaches the Tardigrade process directly. An update to a mounted ConfigMap requires a pod restart (or manual SIGHUP) to take effect — Kubernetes does not signal processes automatically when ConfigMaps change.

## Kubernetes support positioning

| Feature | Status |
|---|---|
| Standalone Deployment | Supported |
| Helm chart | Included in this repo |
| Horizontal Pod Autoscaler | Supported via chart values |
| Kubernetes Ingress controller | Not supported (planned — see #29) |
| Gateway API implementation | Not supported (planned — see #29) |
| Dynamic upstream discovery from Kubernetes endpoints | Not supported (planned — see #30) |

Tardigrade is currently positioned as a **standalone reverse proxy Deployment**, not as a Kubernetes-native Ingress or Gateway API controller. If you want Tardigrade to act as an Ingress controller (watching Ingress resources and configuring itself automatically), that work is tracked in [#29](https://github.com/Bare-Systems/Tardigrade/issues/29).
