#Dockerfile for a Postfix email relay service
#based on https://github.com/juanluisbaptiste/docker-postfix
FROM alpine:latest
MAINTAINER Tony Publiski tonster@tonster.com

RUN apk update && \
    apk add bash gawk cyrus-sasl cyrus-sasl-login cyrus-sasl-crammd5 mailx nagios-plugins-mailq \
    postfix tzdata && \
    rm -rf /var/cache/apk/* && \
    mkdir -p /var/log/supervisor/ /var/run/supervisor/ && \
    sed -i -e 's/inet_interfaces = localhost/inet_interfaces = all/g' /etc/postfix/main.cf

COPY run.sh /
RUN chmod +x /run.sh
RUN newaliases

EXPOSE 25
#ENTRYPOINT ["/run.sh"]
CMD ["/run.sh"]
