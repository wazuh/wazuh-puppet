FROM centos:7

LABEL "com.github.actions.name"="puppet-validate"
LABEL "com.github.actions.description"="Runs Puppet module validation tasks"

LABEL "name"="Validate Wazuh module"
LABEL "version"="0.0.1"
LABEL "repository"="https://github.com/wazuh/wazuh-puppet"
LABEL "maintainer"="Wazuh"

RUN rpm -Uvh https://yum.puppet.com/puppet-tools-release-el-7.noarch.rpm && \
    yum install -y --assumeyes pdk && \
    yum groupinstall -y --assumeyes "Development tools"

COPY ./entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]