#!/bin/bash
OUTPUT_DIRECTORY="output"
container_name="$1"

NUM_RUN=0
if [ "x$2" != "x" ]
then
	NUM_RUNS=$2
fi


d="${OUTPUT_DIRECTORY}/${container_name}_traced/${NUM_RUN}"
if [ ! -f "${d}/result.csv" ]
then
	echo "${d}/result.csv not found"
	exit 1
fi

create_stripped_machine.py ${STRIP_ARGUMENTS} "${STRIP_DOCKERFILE}" "${d}/result.csv" "${container_name}"
