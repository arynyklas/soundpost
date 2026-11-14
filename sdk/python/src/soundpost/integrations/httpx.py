# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
from ..propagation import inject, network_origin
from ..tracing import SpanContextManager

class HTTPXIntegration:
    def __init__(self, client, session, *, operation: str, dependency: str, origin: str, origin_url: str):
        SpanContextManager(client, operation, dependency=dependency, kind='client')
        self.client, self.session = client, session
        self.operation, self.dependency, self.origin = operation, dependency, origin
        self.network_origin = network_origin(origin_url)
        self.enabled = True

    def _request(self, method, url, kwargs, context):
        send_options={key:kwargs.pop(key) for key in ('auth','follow_redirects') if key in kwargs}
        redirects=send_options.get('follow_redirects',self.session.follow_redirects)
        request = self.session.build_request(method, url, **kwargs)
        for key in ('traceparent', 'tracestate', 'baggage'):
            if key in request.headers: del request.headers[key]
        if redirects is False and network_origin(str(request.url)) == self.network_origin:
            request.headers.update(inject(context, self.origin, allowed_origins=self.client._trace_origins))
        return request, send_options

    def request(self, method, url, **kwargs):
        if not self.enabled: return self.session.request(method, url, **kwargs)
        with SpanContextManager(self.client, self.operation, dependency=self.dependency, kind='client') as span:
            request, send_options = self._request(method, url, kwargs, span.context)
            response = self.session.send(request, **send_options)
            if response.status_code >= 500: span.status = 'error'
            return response

class AsyncHTTPXIntegration(HTTPXIntegration):
    async def request(self, method, url, **kwargs):
        if not self.enabled: return await self.session.request(method, url, **kwargs)
        async with SpanContextManager(self.client, self.operation, dependency=self.dependency, kind='client') as span:
            request, send_options = self._request(method, url, kwargs, span.context)
            response = await self.session.send(request, **send_options)
            if response.status_code >= 500: span.status = 'error'
            return response

def install(client, config):
    from . import IntegrationConfig, IntegrationLease
    if type(config) is not IntegrationConfig: raise TypeError('IntegrationConfig required')
    adapter = AsyncHTTPXIntegration if config.asynchronous else HTTPXIntegration
    return IntegrationLease(client, adapter(client, config.target, operation=config.operation, dependency=config.dependency, origin=config.origin, origin_url=config.origin_url))
