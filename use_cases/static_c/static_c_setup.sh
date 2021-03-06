export EXPERIMENT_OPTS="-v /home/local/Desktop/input/disassemble_binary:/input.elf"
export EXPERIMENT_RESULT_FILES="^$"
export CONTAINER="dckr.f4.htw-berlin.de/static_c_container"
export TRACING_APPLICATION="/algorithm -s /input.elf"
export STRIP_ARGUMENTS="--include=/lib64/ld-linux-x86-64.so.2 --include=/algorithm"
export STRIP_DOCKERFILE="/home/local/Desktop/Mac/bb-it-boost-secure-computing/Experimente/ContainerStripping/static_c/static_c_container_stripped/Dockerfile"
export DOCKER_SECURITY="--network=none --pids-limit=1 --cap-drop=CHOWN --cap-drop=MKNOD --cap-drop=SETPCAP --cap-drop=SYS_CHROOT --cap-drop=NET_RAW --cap-drop=SETGID --cap-drop=SETUID --cap-drop=NET_BIND_SERVICE --cap-drop=SETFCAP --cap-drop=FOWNER --security-opt=seccomp=profile.json"
