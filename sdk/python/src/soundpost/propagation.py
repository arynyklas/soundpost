# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Deliberately bounded W3C traceparent propagation without baggage."""
from .context import TraceContext, valid_id

OriginAlias = str
TraceHeaders = dict[str, str]

def extract(headers: TraceHeaders) -> TraceContext | None:
    if type(headers) is not dict:
        return None
    values = [value for key, value in headers.items() if type(key) is str and key.lower() == 'traceparent']
    if len(values) != 1 or type(values[0]) is not str:
        return None
    parts = values[0].split('-')
    if len(parts) != 4 or parts[0] != '00' or not valid_id(parts[1], 32) or not valid_id(parts[2], 16) or parts[3] not in ('00', '01'):
        return None
    return TraceContext(parts[1], parts[2], parts[3] == '01', 1.0)

def inject(context: TraceContext | None, origin: OriginAlias, *, allowed_origins: frozenset[str]) -> TraceHeaders:
    if type(context) is not TraceContext or type(origin) is not str or origin not in allowed_origins:
        return {}
    return {'traceparent': f'00-{context.trace_id}-{context.span_id}-{"01" if context.sampled else "00"}'}

def network_origin(url: str) -> tuple[str, str, int]:
    from urllib.parse import urlsplit
    if type(url) is not str: raise TypeError('URL string required')
    parsed = urlsplit(url)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError('invalid dependency origin')
    return parsed.scheme, parsed.hostname.lower(), parsed.port or (443 if parsed.scheme == 'https' else 80)
