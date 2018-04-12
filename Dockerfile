FROM ubuntu:trusty
LABEL app="GCAT"
LABEL description="General computational analysis tool"
LABEL maintainer="Daniel Wilson"
LABEL build-type="From source"
RUN apt-get -yqq update
RUN apt-get -yqq install make g++ libgsl0-dev libxerces-c3.1
RUN mkdir /tmp/gcat
COPY . /tmp/gcat
RUN make

RUN chmod 755 /tmp/gcat/gcat
RUN chmod 755 /tmp/gcat/lib*
RUN mv /tmp/gcat/gcat /usr/bin/
RUN mv /tmp/gcat/lib* /usr/lib/
WORKDIR /home/ubuntu
ENTRYPOINT ["/usr/bin/gcat"]

