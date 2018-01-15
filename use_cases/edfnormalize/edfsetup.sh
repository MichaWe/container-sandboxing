export EXPERIMENT_OPTS="-v /home/local/Desktop/input/B001501_edfData.edf:/input.edf"
export EXPERIMENT_RESULT_FILES="^/input*"
export CONTAINER="dckr.f4.htw-berlin.de/edfnormalize_container"
export TRACING_APPLICATION="/algorithm data /input.edf"
export STRIP_ARGUMENTS='--exclude="/input*" --exclude="/usr/share/algorithm/output*"'
export STRIP_DOCKERFILE="/pwd/home/local/Desktop/Mac/bb-it-boost-secure-computing/Experimente/ContainerStripping/edfnormalize/edfnormalize_container_stripped/Dockerfile.scratch"
export DOCKER_SECURITY="--network=none --pids-limit=27 --cap-drop=SETGID --cap-drop=NET_BIND_SERVICE --cap-drop=SYS_CHROOT --cap-drop=CHOWN --cap-drop=NET_RAW --cap-drop=SETFCAP --cap-drop=MKNOD --cap-drop=SETPCAP --cap-drop=FOWNER --cap-drop=SETUID --security-opt=seccomp=profile.json"
