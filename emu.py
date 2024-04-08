from qiling import Qiling
from qiling.os.thread import QlThread
from qiling.const import QL_VERBOSE
from collections import defaultdict
from tracer import Tracer

ql = Qiling(
    ["./rootfs/x8664_linux/bin/x8664_hello"],
    rootfs="rootfs/x8664_linux",
    multithread=True,
    verbose=QL_VERBOSE.OFF,
)

tracer = Tracer(ql)

tracer.setup()
ql.run()
tracer.stop()
