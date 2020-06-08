FROM jm404:wazuh-puppet

LABEL "com.github.actions.name"="puppet-tests"
LABEL "com.github.actions.description"="Launch Puppet tests"

LABEL "name"="Validate Wazuh module"
LABEL "version"="0.0.1"
LABEL "repository"="https://github.com/wazuh/wazuh-puppet"
LABEL "maintainer"="Wazuh"

# Adding systemd compatibility.
VOLUME [ "/sys/fs/cgroup", "/run", "/run/lock" ]

ENTRYPOINT ["/entrypoint.sh"]

