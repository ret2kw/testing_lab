FROM w4sp/labs:base

ENV NEWUSER cif
RUN useradd -m $NEWUSER

RUN apt-get -y install git

RUN pip install pyzmq --install-option="--zmq=bundled"
RUN pip install git+https://github.com/csirtgadgets/py-whiteface-sdk.git
RUN pip install git+https://github.com/csirtgadgets/bearded-avenger.git

VOLUME /var/lib

RUN for path in \
    /var/lib/cif/cache \
    /var/lib/cif/rules \
    /var/log/cif \
    ; do \
        mkdir -p $path; \
        chown cif:cif "$path"; \
    done

VOLUME /var/log/cif
VOLUME /var/lib/cif/rules
VOLUME /var/lib/cif/cache

ADD supervisord_cifv3.conf /etc/supervisor/conf.d/supervisor_cifv3.conf

