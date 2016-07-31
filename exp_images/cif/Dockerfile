FROM w4sp/labs:base

#install cif
RUN apt-get -y install git automake
RUN git clone https://github.com/csirtgadgets/massive-octo-spice.git -b master
RUN cd massive-octo-spice && ./autogen.sh && bash ./hacking/platforms/easybutton.sh
RUN chown `whoami`:`whoami` ~/.cif.yml

ADD es_backup es_backup
ADD restore_es.sh restore_es.sh
RUN chown -R elasticsearch:elasticsearch /es_backup

ADD supervisor_cifv2.conf /etc/supervisor/conf.d/supervisor_cifv2.conf

