# Monitoring the Webhook with Grafana and Prometheus

Install the webhook with monitoring and Prometheus Operator ServiceMonitor enabled:

```bash
helm upgrade --wait --install vault-secrets-webhook \
    ./charts/vault-secrets-webhook \
    --namespace vault-infra \
    --set metrics.enabled=true \
    --set metrics.serviceMonitor.enabled=true
```

Install the Prometheus Operator Bundle:

```bash
kubectl apply -f https://raw.githubusercontent.com/coreos/prometheus-operator/master/bundle.yaml
```

Create a Prometheus instance which monitors the Bank-Vaults components:

```bash
kubectl apply -f ./hack/prometheus.yaml
```

Create a Grafana instance instance and expose it:

```bash
kubectl run grafana --image grafana/grafana
kubectl expose deployment grafana --port 3000 --type LoadBalancer
```

Create a Prometheus Data Source in this Grafana instance which grabs data from http://prometheus-operated:9090/.

Import the [Kubewebhook admission webhook dashboard](https://grafana.com/grafana/dashboards/7088) to Grafana by Xabier Larrakoetxea.
Select the previously create Data Source to feed this dashboard.
