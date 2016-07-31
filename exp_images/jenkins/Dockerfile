#import from our base image
FROM w4sp/labs:base

RUN apt-get -y install gdebi
RUN wget --quiet http://pkg.jenkins-ci.org/debian/binary/jenkins_1.610_all.deb
RUN gdebi --option=APT::Get::force-yes=1,APT::Get::Assume-Yes=1 -n jenkins_1.610_all.deb

#add configs for supervisord
ADD supervisor_jenkins.conf /etc/supervisor/conf.d/supervisor_jenkins.conf
