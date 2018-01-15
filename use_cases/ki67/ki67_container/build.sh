#!/bin/bash

TEMP=$(getopt -o t:un:cyr: -l tag:,upload,name:,nocache,yes,registry: -- "$@")
eval set -- "${TEMP}"

CONTAINER_NAME=$(basename $(pwd))
CONTAINER_TAG=latest
CONTAINER_UPLOAD=0
CONTAINER_CACHE=0
CONTAINER_REGISTRY=dckr.f4.htw-berlin.de
REQUIRE_APPROVAL=1

eval set -- "${TEMP}"
while true
do
	case "$1" in
		-t|--tag) CONTAINER_TAG=$2; shift 2;;
		-u|--upload) CONTAINER_UPLOAD=1; shift;;
		-n|--name) CONTAINER_NAME=$2; shift 2;;
		-r|--registry) CONTAINER_REGISTRY=$2; shift 2;;
		-c|--cache) CONTAINER_CACHE=1; shift;;
		-y|--yes) REQUIRE_APPROVAL=0; shift;;
		--) shift; break;;
		*) echo "Internal error!"; exit 1;;
	esac
done

REGISTRY_URL=${CONTAINER_REGISTRY}/${CONTAINER_NAME}
echo "Create container ${CONTAINER_NAME}:${CONTAINER_TAG}"
echo "Use cached container: $([ ${CONTAINER_CACHE} -eq 1 ] && echo yes || echo no)"
echo -n "Upload to registry: "
if [ ${CONTAINER_UPLOAD} -eq 1 ]
then
	echo "yes"
	echo "  Destination: ${REGISTRY_URL}:${CONTAINER_TAG}"
else
	echo "no"
fi

if [ ${REQUIRE_APPROVAL} -ne 0 ]
then
	echo -n "Proceed? [y/n]: "
	read answer
	if [ "x${answer}" != "xy" -a "x${answer}" != "xY" -a "x${answer}" != "xyes" ]
	then
		echo "Cancelled on user request"
		exit 0
	fi
fi

docker pull ${REGISTRY_URL}

if [ ${CONTAINER_CACHE} -eq 1 ]
then
	docker build -t ${REGISTRY_URL} .
else
	docker build --no-cache -t ${REGISTRY_URL} .
fi

if [ ${CONTAINER_UPLOAD} -eq 1 ]
then
	if [ ! -z "${CONTAINER_TAG}" -a "${CONTAINER_TAG}" != "latest" ]
	then
		docker tag ${REGISTRY_URL} ${REGISTRY_URL}:${CONTAINER_TAG}
		docker push ${REGISTRY_URL}:${CONTAINER_TAG}
	else
		docker push ${REGISTRY_URL}
	fi
fi
