#!/bin/bash

# specify your experiment options here
#EXPERIMENT_OPTS="-v /home/local/Desktop/input/B001501_edfData.edf:/input.edf"
#EXPERIMENT_RESULT_FILES="^/input"
#CONTAINER="dckr.f4.htw-berlin.de/edfnormalize_container"
TIME_FORMAT="arguments=%C\nunshared_data_size_k=%D\nt_elapsed_s=%e\nmajor_page_faults=%F\nfs_inputs=%I\navg_total_memory_k=%K\nmax_memory_k=%M\nio_outputs=%O\ncpu_load=%P\nminor_page_faults=%R\nsystem_cpu_time=%S\nuser_cpu_time=%U\nnum_swaps=%W\nshared_text_size_k=%X\nsystem_page_size=%Z\nnum_hard_context_switches=%c\nnum_signals=%k\navg_unshared_stack_size_k=%p\nnum_recv_socket_messages=%r\nnum_send_socket_messages=%s\navg_memory_k=%t\nnum_weak_context_switches=%w\nexit_code=%x"

TRACING_DIST="/home/local/tracer.dist"
#TRACING_APPLICATION="/algorithm data /input.edf"

OUTPUT_DIRECTORY="output"
NUM_RUNS=1
if [ "x$2" != "x" ]
then
	NUM_RUNS=$2
fi

container_name="$1_traced"

mkdir -p /tmp/__tracing_output
for ((i=0;i<${NUM_RUNS};i++))
do
	docker rm -f "${container_name}"
	d="${OUTPUT_DIRECTORY}/${container_name}/${i}"
	rm -rf "${d}"
	mkdir -p "${d}"
	/usr/bin/time -q -f "${TIME_FORMAT}" -o "${d}/stats.txt" -- docker run --name "${container_name}" ${EXPERIMENT_OPTS} -v "${TRACING_DIST}":/tracer.dist -v /tmp/__tracing_output:/usr/share/algorithm/output -e TRACE_COMMAND="${TRACING_APPLICATION}" --security-opt=seccomp:unconfined ${CONTAINER} /tracer.dist/tracer.exe > "${d}/output.txt" 2>&1
	docker diff "${container_name}" | egrep "^A" | sed 's#^A ##' | egrep "${EXPERIMENT_RESULT_FILES}" | while read file; do docker cp "${container_name}":"$file" "${d}/"; done
	cp /tmp/__tracing_output/output.txt "${d}/output.tracing.txt"
	cp /tmp/__tracing_output/result.csv "${d}/result.csv"
	cat "${d}/stats.txt"
done
rm -rf /tmp/__tracing_output
