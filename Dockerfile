FROM centos:7

ADD _output/snowstorm /usr/bin/snowstorm
EXPOSE 8080

CMD ["/usr/bin/snowstorm", "-alsologtostderr", "-logtostderr"]
