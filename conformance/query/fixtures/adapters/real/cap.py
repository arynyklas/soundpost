import http.server, json, os, threading
OUT='/out'; os.makedirs(OUT,exist_ok=True)
OM=b'''# HELP soundpost_fixture_requests Requests served by the fixture.
# TYPE soundpost_fixture_requests counter
# UNIT soundpost_fixture_requests requests
soundpost_fixture_requests_total{method="get",code="200"} 1027 # {trace_id="0af7651916cd43dd8448eb211c80319c",span_id="b7ad6b7169203331"} 1 1700000000.123
soundpost_fixture_requests_total{method="post",code="500"} 3
soundpost_fixture_requests_created{method="get",code="200"} 1700000000.0
# HELP soundpost_fixture_temperature_celsius Room temperature.
# TYPE soundpost_fixture_temperature_celsius gauge
# UNIT soundpost_fixture_temperature_celsius celsius
soundpost_fixture_temperature_celsius{room="lab"} 21.5
soundpost_fixture_temperature_celsius{room="cellar"} -3.25
# HELP soundpost_fixture_latency_seconds Request latency.
# TYPE soundpost_fixture_latency_seconds histogram
# UNIT soundpost_fixture_latency_seconds seconds
soundpost_fixture_latency_seconds_bucket{le="0.1"} 5
soundpost_fixture_latency_seconds_bucket{le="0.5"} 12
soundpost_fixture_latency_seconds_bucket{le="2.5"} 14
soundpost_fixture_latency_seconds_bucket{le="+Inf"} 15
soundpost_fixture_latency_seconds_sum 9.75
soundpost_fixture_latency_seconds_count 15
# EOF
'''
n={'v1':0,'v2':0}
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type','application/openmetrics-text; version=1.0.0; charset=utf-8')
        self.end_headers(); self.wfile.write(OM)
        if not os.path.exists(OUT+'/scrape.om'): open(OUT+'/scrape.om','wb').write(OM)
    def do_POST(self):
        body=self.rfile.read(int(self.headers['Content-Length']))
        k='v2' if 'v2' in self.path else 'v1'
        n[k]+=1
        open(f'{OUT}/rw-{k}-{n[k]:03d}.bin','wb').write(body)
        json.dump({h:self.headers[h] for h in self.headers},open(f'{OUT}/rw-{k}-{n[k]:03d}.headers.json','w'))
        self.send_response(204)
        if k=='v2':
            for h in ('X-Prometheus-Remote-Write-Samples-Written','X-Prometheus-Remote-Write-Histograms-Written','X-Prometheus-Remote-Write-Exemplars-Written'):
                self.send_header(h,'0')
        self.end_headers()
http.server.ThreadingHTTPServer(('0.0.0.0',9000),H).serve_forever()
