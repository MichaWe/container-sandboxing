#!/bin/bash
SCHEDULER_PATH="https://studi.f4.htw-berlin.de/~michael/mini_scheduler.php"
OUTPUT_FILENAME="/tmp/tile.png"
PROCESSOR="/ki67/Ki67Analyser.exe"
NUM_THREADS=1

while true
do
	next_path=$(curl -s ${SCHEDULER_PATH})

	# Verify input
	if [ $? -ne 0 -o "x${next_path}" = "xDONE" -o "x${next_path}" = "xERROR" -o "x${next_path}" = "x" ]
	then
		echo "Failed to fetch image"
		break;
	fi

	# We have a valid path
	# Download the input file
	curl -s -L -o "${OUTPUT_FILENAME}" "${next_path}"
        real_filename=$(echo "${next_path}" | sed "s#.*/##" | sed "s#\?.*##")
	
	# Verify download
	if [ $? -ne 0 -o ! -f "${OUTPUT_FILENAME}" ]
	then
		echo "Failed to download image"
		break;
	fi

	# Run the calculation
	result=$(mono ${PROCESSOR} "${OUTPUT_FILENAME}" ${NUM_THREADS})
	# Verify input
        if [ $? -ne 0 -o "x${result}" = "x" ]
        then
		echo "Mono failed to run"
                break;
        fi

	curl -X POST -d "hash=${real_filename}&result=${result}" -s ${SCHEDULER_PATH}
	rm "${OUTPUT_FILENAME}"
done

