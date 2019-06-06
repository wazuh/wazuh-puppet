class wazuh::elasticsearch (
  
){

  include "wazuh::repo_elastic"

  require "wazuh::params_elastic"

  file { 'Configure elasticsearch.yml':
    owner   => 'root',
    group   => $wazuh::params_elastic::config_group,
    mode    => $wazuh::params_elastic::config_mode,
    notify  => Service[$wazuh::params_elastic::server_service],
    require => Package[$wazuh::params_elastic::server_package];
  '/etc/elasticsearch/elasticsearch.yml':
    content => template("elasticsearch_yml.erb");
  }

  exec { 'Insert line limits.. ':
    command => '<<-EOH
                echo "elasticsearch - nofile  65535" >> /etc/security/limits.conf
                echo "elasticsearch - memlock unlimited" >> /etc/security/limits.conf
                EOH'
  }
}
