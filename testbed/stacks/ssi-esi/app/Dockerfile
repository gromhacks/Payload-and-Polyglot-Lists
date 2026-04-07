FROM httpd:2.4-alpine
COPY httpd-ssi.conf /usr/local/apache2/conf/extra/httpd-ssi.conf
RUN echo 'Include conf/extra/httpd-ssi.conf' >> /usr/local/apache2/conf/httpd.conf
COPY htdocs/ /usr/local/apache2/htdocs/
