FROM debian:stretch
MAINTAINER "Michael Witt"

RUN apt update && apt install -y libdistorm3-3 libglib2.0-0

# Copy ki67 binaries
COPY disassemble_binary /algorithm

CMD [ "/algorithm", "-s", "/input.elf" ]
