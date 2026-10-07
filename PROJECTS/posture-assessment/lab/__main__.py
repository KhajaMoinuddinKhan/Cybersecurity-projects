"""Start the lab broker from the command line.

`python -m lab` runs the open broker, which is the vulnerable configuration, so the
IoT arm can be pointed at a real service the way it is meant to be used.
"""

from __future__ import annotations

import os

from .broker import Broker
from . import manifest

if __name__ == "__main__":
    declared = manifest()
    print("the lab declares %d artifacts" % len(declared["artifacts"]))
    broker = Broker(port=int(os.environ.get("LAB_MQTT_PORT") or 1883),
                    allow_anonymous=os.environ.get("LAB_MQTT_OPEN", "1") != "0")
    broker.start()
    print("the lab broker is listening on %s, anonymous access %s"
          % (broker.address, "allowed" if broker.allow_anonymous else "refused"))
    try:
        while True:
            import time
            time.sleep(3600)
    except KeyboardInterrupt:
        broker.stop()
