# Deployment

The first reference Compose foundation is stored at the repository root as `compose.yaml`, so local development can use `docker compose up` without additional flags. See [docs/development.md](../docs/development.md).

This is not a production release: it provides PostgreSQL, migrations, health endpoints, and an inert worker process. Mail ingestion, the setup UI, HTTPS proxy, backup workflow, and release images are not implemented yet.
