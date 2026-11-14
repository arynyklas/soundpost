# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
import logging

class TemplateHandler(logging.Handler):
    """Only explicit template IDs and plain field dictionaries are admitted."""
    def __init__(self, client):
        super().__init__()
        self.client = client

    def emit(self, record):
        if type(record) is not logging.LogRecord: return
        values = object.__getattribute__(record, '__dict__')
        template, fields = values.get('soundpost_template'), values.get('soundpost_fields')
        if type(template) is str and type(fields) is dict:
            self.client.capture_log(template, fields)

class LoggingLease:
    def __init__(self, client, logger: logging.Logger):
        if type(logger) is not logging.Logger: raise TypeError('Logger required')
        self.logger = logger
        self.handler = TemplateHandler(client)
        self.closed = False
        self.client = client
        client._own_hook_lease(self)
        logger.addHandler(self.handler)

    def close(self):
        if not self.closed:
            self.closed = True
            self.logger.removeHandler(self.handler)
            self.handler.close()
            self.client._release_hook_lease(self)

def install(client, config):
    from . import IntegrationConfig
    if type(config) is not IntegrationConfig: raise TypeError('IntegrationConfig required')
    return LoggingLease(client, config.target)
