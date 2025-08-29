# Omni Telemetry

## Setting up single-node RKE2 cluster

```
curl -sfL https://get.rke2.io | sh -
```

Configuration:

```yaml
# file: /etc/rancher/rke2/config.yaml
tls-san:
  - rke2.omni.accuknox.com
disable:
  - rke2-ingress-nginx
```

## Installing local-path-provisioner

```
helm install local-path-storage --create-namespace --namespace local-path-storage charts/local-path-provisioner/
```

## Installing Cert-Manager

```
helm install cert-manager oci://quay.io/jetstack/charts/cert-manager \
  --version v1.18.2 \
  --namespace cert-manager \
  --create-namespace \
  --values ./charts/cert-manager/values.yaml
```

## Installing Istio

```
helm repo add istio https://istio-release.storage.googleapis.com/charts
helm repo update

version="1.27.0"

helm install istio-base istio/base \
    --namespace istio-system \
    --create-namespace \
    --version "$version"

helm install istiod istio/istiod \
    --namespace istio-system \
    --create-namespace \
    --version "$version"

helm install istio-ingressgateway istio/gateway \
    --namespace istio-system \
    --create-namespace \
    --version "$version"
```

## Creating LetsEncrypt Cluster Issuers

```
kubectl apply -f letsencrypt-issuers.yaml
```

## Installing Kube Prometheus Stack

```
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update
helm upgrade kube-prometheus-stack prometheus-community/kube-prometheus-stack \
    --version 77.0.2 \
    --install \
    --namespace monitoring \
    --create-namespace \
    --values ./charts/kube-prometheus-stack/values.yaml

# expose grafana to the internet
kubectl apply -f grafana-ingress.yaml
```

## Installing Loki

```
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update
helm upgrade loki grafana/loki \
    --version 6.37.0 \
    --install \
    --namespace monitoring \
    --create-namespace \
    --values ./charts/loki/values.yaml
```

## Installing Otel Gateway Collector

```
helm repo add open-telemetry https://open-telemetry.github.io/opentelemetry-helm-charts
helm repo update
helm upgrade opentelemetry-operator open-telemetry/opentelemetry-operator \
    --version 0.93.0 \
    --install \
    --namespace opentelemetry \
    --create-namespace \
    --set manager.collectorImage.repository=otel/opentelemetry-collector-contrib

kubectl apply -f otel-collector-gateway.yaml -f otel-collector.yaml -f servicemonitor.yaml
```
