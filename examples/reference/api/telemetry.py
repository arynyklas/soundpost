# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Shared SDK wiring for the reference Python apps (API and jobs worker).

The Soundpost SDK is optional behind --config: without it the helpers below
call psycopg/httpx directly and nothing is recorded.
"""
import base64
import json
import ssl
from pathlib import Path

REFERENCE_ROOT = str(Path(__file__).resolve().parent.parent)
OPERATIONS = ("request", "http.call", "db.execute", "job.run", "ui.action")
DEPENDENCIES = ("api", "postgres", "dependency", "gateway")
ORIGINS = ("dependency",)


def load_client(path):
    """Initialise the SDK client from the parent-written JSON config."""
    from soundpost import Config, Resource, RoutingDescriptor, SignedPolicy, init

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    res = data["resource"]
    keys = {name: base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)) for name, value in data["trusted_keys"].items()}
    config = Config(
        org=data["org"], project=data["project"], source=data["source"], endpoint=data["endpoint"],
        credential=data["credential"], build=data["build"],
        resource=Resource(res["service_id"], res["environment_id"], res["build_id"], res["instance_pseudonym"],
                          tuple((label["name"], label["value"]) for label in res.get("labels", []))),
        descriptor=RoutingDescriptor(**data["descriptor"]), policy=SignedPolicy(**data["policy"]),
        trusted_keys=keys, ca_file=data.get("ca_file"),
        operations=OPERATIONS, dependencies=DEPENDENCIES, origins=ORIGINS,
        job_registry=tuple(sorted(data.get("job_registry", {}).items())),
        deployment_errors=True, deployment_traces=True, deployment_jobs=True,
        project_root=REFERENCE_ROOT,
    )
    return init(config), data


def http_client(ca_file, timeout=10.0):
    import httpx
    context = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
    return httpx.Client(verify=context, follow_redirects=False, timeout=timeout)


class Instruments:
    """psycopg/httpx entry points; SDK-wrapped when a client exists."""

    def __init__(self, client, http, dependency_url):
        self.client, self.http, self.dependency_url = client, http, dependency_url.rstrip("/")
        self._http = None
        if client is not None:
            from soundpost.integrations.httpx import HTTPXIntegration
            self._http = HTTPXIntegration(client, http, operation="http.call", dependency="dependency",
                                          origin="dependency", origin_url=self.dependency_url)

    def post_dependency(self, path, **kwargs):
        url = self.dependency_url + path
        if self._http is not None:
            return self._http.request("POST", url, **kwargs)
        return self.http.request("POST", url, **kwargs)

    def database(self, connection):
        if self.client is None:
            return connection
        from soundpost.integrations.psycopg import PsycopgIntegration
        return PsycopgIntegration(self.client, connection, operation="db.execute", dependency="postgres")

    def capture(self, error, code):
        """Record a handled error through the SDK; no-op without telemetry."""
        if self.client is None:
            return
        episode = self.client.begin_handling_episode()
        try:
            episode.capture_exception(error, code=code)
        finally:
            episode.close()


def finish(client, timeout=10.0):
    """Flush then close; returns ({"pending","lost","receipts"}, clean)."""
    if client is None:
        return None, True
    report = client.flush(timeout)
    if report.pending:
        report = client.flush(timeout)
    result = {"pending": report.pending, "lost": report.lost, "receipts": len(report.receipts)}
    client.close()
    return result, report.pending == 0 and report.lost == 0
