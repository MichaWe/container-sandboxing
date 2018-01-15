FROM mono:latest
MAINTAINER "Michael Witt"

# Copy ki67 binaries
COPY ki67 /ki67/

# Setup xnat environment paths
ENV PATH /ki67/:$PATH
ENV KI67_HOME /ki67/

CMD [ "mono", "/ki67/Ki67Analyser.exe", "/input.png", "1" ]
