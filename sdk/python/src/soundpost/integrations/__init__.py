# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Explicit per-client adapters; installation never patches runtime globals."""
from dataclasses import dataclass, field

@dataclass(frozen=True)
class IntegrationConfig:
    target: object = field(repr=False)
    operation: str = ''
    dependency: str = ''
    origin: str = ''
    origin_url: str = field(default='', repr=False)
    asynchronous: bool = False

class IntegrationLease:
    def __init__(self, client, adapter):
        self.client, self.adapter = client, adapter
        self.closed = False
        client._own_hook_lease(self)

    def close(self):
        if self.closed: return
        self.closed = True
        self.adapter.enabled = False
        self.client._release_hook_lease(self)

    def __enter__(self): return self.adapter
    def __exit__(self, *error): self.close()
