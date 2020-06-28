FROM debian:latest
WORKDIR /home
RUN apt update && apt install -y python3-pip python3-apt python curl && pip3 install simplejson urllib3 && curl https://bootstrap.pypa.io/get-pip.py --output get-pip.py && python get-pip.py && pip3 install --upgrade pip
