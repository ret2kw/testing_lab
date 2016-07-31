FROM scratch

ADD hardy-chroot /
ADD sources.list /etc/apt/sources.list

#modified by @ret2kw to mimic some of the metasploitable stuff
MAINTAINER Dennis Sänger <mail@dennis.io>

ENV DEBIAN_FRONTEND noninteractive

RUN echo '#!/bin/sh' > /usr/sbin/policy-rc.d \
	&& echo 'exit 101' >> /usr/sbin/policy-rc.d \
	&& chmod +x /usr/sbin/policy-rc.d \
	\
	&& dpkg-divert --local --rename --add /sbin/initctl \
	&& cp -a /usr/sbin/policy-rc.d /sbin/initctl \
	&& sed -i 's/^exit.*/exit 0/' /sbin/initctl \
	\
	&& mkdir -p etc/dpkg/dpkg.cfg.d \
	&& echo 'force-unsafe-io' > /etc/dpkg/dpkg.cfg.d/docker-apt-speedup \
	\
	&& echo 'DPkg::Post-Invoke { "rm -f /var/cache/apt/archives/*.deb /var/cache/apt/archives/partial/*.deb /var/cache/apt/*.bin || true"; };' > /etc/apt/apt.conf.d/docker-clean \
	&& echo 'APT::Update::Post-Invoke { "rm -f /var/cache/apt/archives/*.deb /var/cache/apt/archives/partial/*.deb /var/cache/apt/*.bin || true"; };' >> /etc/apt/apt.conf.d/docker-clean \
	&& echo 'Dir::Cache::pkgcache ""; Dir::Cache::srcpkgcache "";' >> /etc/apt/apt.conf.d/docker-clean \
	\
	&& echo 'Acquire::Languages "none";' > /etc/apt/apt.conf.d/docker-no-languages \
	\
	&& echo 'Acquire::GzipIndexes "true"; Acquire::CompressionTypes::Order:: "gz";' > /etc/apt/apt.conf.d/docker-gzip-indexes


#update and get the libs we need for vsftpd
RUN apt-get update && apt-get -y build-dep vsftpd
#install prereqs and rmiregistry
RUN apt-get -y install logrotate xinetd java-gcj-compat-headless
RUN apt-get -y install bridge-utils ethtool
RUN apt-get -y install iptables

#move over our vulnerable software ripped from metasploitable2
ADD vuln /vuln

#install the vulnerable samba
RUN dpkg -i /vuln/samba/samba-common_3.0.20-0.1ubuntu1_i386.deb
RUN dpkg -i /vuln/samba/samba_3.0.20-0.1ubuntu1_i386.deb
RUN dpkg -i /vuln/samba/winbind_3.0.20-0.1ubuntu1_i386.deb

#update dhclient
RUN apt-get -y install dhcp3-client

#copy over configuration files
RUN cd /vuln/samba && cp -r samba/* /etc/samba

#'install' vulnerable vsftpd
RUN cp /vuln/vsftpd/vsftpd /usr/sbin/ && cp /vuln/vsftpd/vsftpd.conf /etc/vsftpd.conf && cp /vuln/vsftpd/xinetd.d/vsftpd /etc/xinetd.d/ 
#add the ftp user and directory
RUN useradd -c "FTP User" -d /home/ftp -r -s /bin/false ftp && mkdir -p /usr/share/empty

#add the startup script that will spin up the vulnerable services
ADD start_sploits.sh /start_sploits.sh
RUN chmod +x /start_sploits.sh

# overwrite this with 'CMD []' in a dependent Dockerfile
ENTRYPOINT ["/start_sploits.sh"]

