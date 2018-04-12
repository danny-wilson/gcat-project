FROM ubuntu:trusty
LABEL app="GCAT"
LABEL description="General computational analysis tool"
LABEL maintainer="Daniel Wilson"
LABEL build-type="From source"
RUN apt-get -yqq update
RUN apt-get -yqq install make g++ libgsl0-dev libxerces-c-dev
RUN mkdir /tmp/gcat
COPY . /tmp/gcat
RUN make
RUN mv /tmp/gcat/gcat /usr/bin/
RUN mv /tmp/gcat/lib* /usr/lib/
RUN cd /tmp/gcat/examples && gcat test.xml
WORKDIR /home/ubuntu
ENTRYPOINT ["/usr/bin/gcat"]
