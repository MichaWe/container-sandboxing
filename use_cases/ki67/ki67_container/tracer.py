#!/usr/bin/env python3

import signal
import posix
import sys
import os
import shlex
from subprocess import Popen, PIPE
from process_tracing.tracing import Tracing
from process_tracing.constants import TRACING_RECORD_MODE_FILE

TRACING_FILENAME="/usr/share/algorithm/output/result.csv"
OUTPUT_FILENAME="/usr/share/algorithm/output/output.txt"

# Setup the command to run
command = sys.argv[1:]
if os.environ.get("TRACE_COMMAND"):
    command = shlex.split(os.environ.get("TRACE_COMMAND"))

# Open the command pipe
p = Popen(command, stdout=PIPE, stderr=PIPE, shell=False)
tracer = Tracing(p.pid, stop=True, recording_mode=TRACING_RECORD_MODE_FILE, log_filename=TRACING_FILENAME)
tracer.runtime_tracing = True
tracer.file_access_detailed_tracing = True
tracer.syscall_tracing = True
tracer.syscall_argument_tracing = True

tracer.start()

stdout, stderr = p.communicate()
tracer.wait()

with open(OUTPUT_FILENAME, "w") as fd:
    fd.write("Standard out:\n{}\nStandard error:\n{}\n".format(stdout.decode('utf-8'), stderr.decode('utf-8')))
