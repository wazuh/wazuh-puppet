FROM alpine:3.11


LABEL "com.github.actions.name"="puppet-validate"
LABEL "com.github.actions.description"="Runs Puppet module validation tasks"

LABEL "name"="Validate Wazuh module"
LABEL "version"="0.0.1"
LABEL "repository"="https://github.com/wazuh/wazuh-puppet"
LABEL "maintainer"="Wazuh"

ENV PDK_DISABLE_ANALYTICS=true \
    PUPPET_DEVELOPMENT_KIT_VERSION=1.18.0

RUN apk add --no-cache \
    build-base \
    libffi-dev \
    ruby \
    ruby-dev \
    ruby-io-console \
    bash \
    curl \
    jq

RUN gem install \
    --no-document \
    'json:2.3.0' \
    'pdk:$PUPPET_DEVELOPMENT_KIT_VERSION'

RUN gem update --system

ADD entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]