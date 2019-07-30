FROM centos:7
ENV container docker
RUN yum clean all
RUN yum install -y sudo openssh-server openssh-clients which curl
RUN [ -f "/etc/ssh/ssh_host_rsa_key" ] || ssh-keygen -t rsa -f /etc/ssh/ssh_host_rsa_key -N ''
RUN [ -f "/etc/ssh/ssh_host_dsa_key" ] || ssh-keygen -t dsa -f /etc/ssh/ssh_host_dsa_key -N ''
RUN if ! getent passwd kitchen; then                 useradd -d /home/kitchen -m -s /bin/bash -p '*' kitchen;               fi
RUN echo "kitchen ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
RUN echo "Defaults !requiretty" >> /etc/sudoers
RUN mkdir -p /home/kitchen/.ssh
RUN chown -R kitchen /home/kitchen/.ssh
RUN chmod 0700 /home/kitchen/.ssh
RUN touch /home/kitchen/.ssh/authorized_keys
RUN chown kitchen /home/kitchen/.ssh/authorized_keys
RUN chmod 0600 /home/kitchen/.ssh/authorized_keys
RUN mkdir -p /run/sshd
RUN echo ssh-rsa\ AAAAB3NzaC1yc2EAAAADAQABAAABAQDJKUBDqOuQpdb0e40w/C\+Nch8cy1gz2zKIVddWXsz8334\+g9SW7tkc5E0og3gItEAIao0qBIZcsLQCre\+un66Dz2P7NoYXK9LVWWdj/ujksxkloCRk28bDV2vQTUZ7pOQsBI0U6s/T4QnpGZP9OM2RuqacnCc0tWahXKBWKlODmDAEMGM5q\+jjjQunGHk4b\+\+TDWS8HF/rCAgEQF3Bh0SNAZudJpOwwtu54YhHYxDt\+tGCG4tJqFpyl1CRyKPwEN2M0Ccz9kvyXQqc6lg8ULH2bMIcE8TSFJN53Zi6y6E2ZwihSE5O2ybs3KYmrXviy\+1l2Y4yOpk9NgD07giEZEBR\ kitchen_docker_key >> /home/kitchen/.ssh/authorized_keys
EXPOSE 1515/tcp
EXPOSE 1515/udp
RUN yum install -y openssl
