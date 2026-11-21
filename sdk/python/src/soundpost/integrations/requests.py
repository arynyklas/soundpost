# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
from ..propagation import inject, network_origin
from ..tracing import SpanContextManager

class RequestsIntegration:
    """Explicit session adapter; no global monkeypatch or raw URL capture."""
    def __init__(self, client, session, *, operation: str, dependency: str, origin: str, origin_url: str):
        SpanContextManager(client, operation, dependency=dependency, kind='client')
        self.client, self.session = client, session
        self.operation, self.dependency, self.origin = operation, dependency, origin
        self.network_origin = network_origin(origin_url)
        self.enabled = True

    def request(self, method, url, **kwargs):
        if not self.enabled: return self.session.request(method, url, **kwargs)
        with SpanContextManager(self.client, self.operation, dependency=self.dependency, kind='client') as span:
            headers = {k:v for k,v in kwargs.pop('headers', {}).items() if k.lower() not in ('traceparent','tracestate','baggage')}
            if kwargs.get('allow_redirects') is False and network_origin(url) == self.network_origin:
                headers.update(inject(span.context, self.origin, allowed_origins=self.client._trace_origins))
            # Session-level baggage must not bypass the explicit origin gate.
            for key in ('traceparent', 'tracestate', 'baggage'):
                if key not in headers: headers[key] = None
            response = self.session.request(method, url, headers=headers, **kwargs)
            if response.status_code >= 500: span.status = 'error'
            return response

def install(client, config):
    from . import IntegrationConfig, IntegrationLease
    if type(config) is not IntegrationConfig: raise TypeError('IntegrationConfig required')
    return IntegrationLease(client, RequestsIntegration(client, config.target, operation=config.operation, dependency=config.dependency, origin=config.origin, origin_url=config.origin_url))
