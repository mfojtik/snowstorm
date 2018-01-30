FROM centos:7

EXPOSE 8080
RUN mkdir -p /opt/snowstorm
WORKDIR /opt/snowstorm

ADD _output/amd64/snowstorm /usr/bin/snowstorm
COPY ./static/* /opt/snowstorm

CMD ["/usr/bin/snowstorm", "-alsologtostderr", "-logtostderr"]
