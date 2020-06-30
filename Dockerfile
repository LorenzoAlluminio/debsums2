FROM debian:latest
WORKDIR /home
RUN apt update && apt install -y python-pip python3-pip python3-apt && python3 -m pip install --upgrade pip && python2 -m pip install --upgrade pip && pip3 install simplejson urllib3
