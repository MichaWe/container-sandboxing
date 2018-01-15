FROM docker.io/debian:jessie

# Install process tracing library
RUN apt-get update
RUN apt-get install -y apt-utils git 

# Install Matlab
RUN mkdir /mcr-install
COPY MCR_R2015a_glnxa64_installer.zip /mcr-install/installer.zip

RUN apt-get install -y curl unzip libxt6
RUN unzip /mcr-install/installer.zip -d /mcr-install
RUN /mcr-install/install -agreeToLicense yes -mode silent
RUN rm -rf /mcr-install

RUN apt-get install -y net-tools curl

ENV LD_LIBRARY_PATH $LD_LIBRARY_PATH:/usr/local/MATLAB/MATLAB_Runtime/v85/runtime/glnxa64:/usr/local/MATLAB/MATLAB_Runtime/v85/bin/glnxa64:/usr/local/MATLAB/MATLAB_Runtime/v85/sys/os/glnxa64
COPY sn_edfScan2edfData /algorithm
COPY psg_channelmap.txt /psg_channelmap.txt

WORKDIR "/"
CMD ["/algorithm", "data", "/input.edf"]
