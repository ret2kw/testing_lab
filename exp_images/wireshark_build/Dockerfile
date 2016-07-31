FROM kalilinux/kali-linux-docker

RUN apt-get -y update && apt-get -y upgrade

RUN apt-get -y install git build-essential

#clone the wireshark git repo
RUN git clone https://code.wireshark.org/review/wireshark

#dependencies for autogen.sh & configure
RUN apt-get -y install python automake autoconf libtool-bin pkg-config bison flex

#dependencies for basic wireshark
RUN apt-get -y install qt5-default libgtk-3-dev libpcap-dev 

#dependencies for additional features
RUN apt-get -y install libssh-dev libcap-dev libkrb5-dev liblua5.2-dev portaudio19-dev \
    libgeoip-dev libc-ares-dev libsmi2-dev libgcrypt20-dev libgnutls28-dev libnl-cli-3-dev libsbc-dev

#checkout stable version
RUN cd wireshark && git fetch && git checkout -b working remotes/origin/master-2.0

RUN apt-get -y install checkinstall 

#dependencies for configure, don't enable setcap as it breaks install
RUN cd wireshark && ./autogen.sh && ./configure --with-ssl --enable-tfshark --with-pcap-remote --with-extcap --program-prefix="w4sp_" --disable-dependency-tracking

#install it
RUN cd wireshark && make -j4


