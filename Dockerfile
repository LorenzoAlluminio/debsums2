FROM debian:latest
WORKDIR /home
RUN apt update && apt install -y python-pip python3-pip python3-apt && pip3 install simplejson urllib3
