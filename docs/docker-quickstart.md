# Docker quickstart

Docker Compose starts the RD Guard V11.4.0 API, Prometheus, and Grafana. From the
repository root:

```sh
docker-compose up -d
```

The first run builds the app image and may take a few minutes. Check service
health and the API response:

```sh
docker-compose ps
curl http://localhost:8000/
```

The API should return `"status": "V11.4.0 LIVE"`. Prometheus is available at
<http://localhost:9090>; Grafana is at <http://localhost:3000> and uses the
development-only default credentials `admin` / `admin`. The provisioned RD Guard
dashboard is available in Grafana's dashboards list.

Prometheus scrapes the app's internal `app:9090/metrics` endpoint. Try these
queries at <http://localhost:9090/graph>:

```promql
rd_guard_safety_state
sum by (decision) (rate(rd_guard_action_decisions_total[5m]))
histogram_quantile(0.99, sum by (le) (rate(rd_guard_observe_duration_seconds_bucket[5m])))
```

To stop the services while retaining Prometheus and Grafana data:

```sh
docker-compose down
```

To remove the persistent monitoring data as well:

```sh
docker-compose down -v
```

Do not use the default Grafana credentials or this development Compose setup
unchanged in a production environment. See the [deployment guide](deployment.md)
for production requirements.
