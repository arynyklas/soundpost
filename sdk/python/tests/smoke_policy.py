# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
import json
from test_policy import config, Trap
from soundpost import init
c=init(config())
c.capture_exception(Trap("PRIVATE_CANARY"))
c.capture_log("operation.failed",{"status":503,"sql":"PRIVATE_CANARY","credential":"SECRET"})
data=json.dumps({"records":c.buffered_records(),"diagnostics":c.diagnostics()})
assert "PRIVATE_CANARY" not in data and "SECRET" not in data
assert "Trap" in data and "operation.failed" in data
record=json.loads(c.buffered_records()[0])
assert record["observed_at_ns"]=="9007199254740993"
print(json.dumps({"records":len(c.buffered_records()),"privacy_canaries":0,"observed_at_ns":record["observed_at_ns"]}))
