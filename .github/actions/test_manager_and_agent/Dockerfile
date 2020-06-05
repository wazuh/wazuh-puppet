FROM ubuntu:18.04

LABEL "com.github.actions.name"="puppet-tests"
LABEL "com.github.actions.description"="Launch Puppet tests"

LABEL "name"="Validate Wazuh module"
LABEL "version"="0.0.1"
LABEL "repository"="https://github.com/wazuh/wazuh-puppet"
LABEL "maintainer"="Wazuh"


VOLUME [ "/sys/fs/cgroup", "/run", "/run/lock" ]
COPY ./entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

