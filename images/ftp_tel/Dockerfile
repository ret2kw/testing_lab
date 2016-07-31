#build off of w4sp base image
FROM w4sp/labs:base

RUN apt-get install -y vsftpd telnetd apache2

##setup vsftpd
RUN mkdir -p /var/run/vsftpd/empty
#make it so we can write files
RUN echo 'write_enable=YES' >> /etc/vsftpd.conf

##setup apache
#add html pages
RUN mkdir -p /var/www/ssl
ADD ssl.html /var/www/ssl/index.html
ADD http.html /var/www/html/index.html
#fix up perms
RUN chown -R www-data:www-data /var/www/
#enable ssl
RUN a2enmod ssl 
#add the ssl config
ADD default-ssl.conf /etc/apache2/sites-available/default-ssl.conf
#add over the keyfiles
ADD apache.crt /etc/ssl/certs/apache.crt
ADD apache.key /etc/ssl/private/apache.key
#enable conf
RUN a2ensite default-ssl.conf


ADD supervisor_ftptel.conf /etc/supervisor/conf.d/supervisor_ftpel.conf
