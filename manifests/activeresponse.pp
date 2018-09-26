# Wazuh App Copyright (C) 2018 Wazuh Inc. (License GPLv2)
#Define for a specific ossec active-response
define wazuh::activeresponse(
  String $command_name,
  Enum['local', 'server', 'defined-agent', 'all']  $ar_location = 'local',
  Integer[0, 16] $ar_level      = 7,
  String $ar_agent_id           = '',
  Integer $ar_order             = 55,
  Array[String] $ar_rules_id    = [],
  Integer[0] $ar_timeout        = 300,
  String $ar_repeated_offenders = '',
) {
  # Build active response fragment
  concat::fragment { "ossec.conf_activeresponse-${title}":
    target  => 'ossec.conf',
    order   => $ar_order,
    content => template('wazuh/fragments/_activeresponse.erb')
  }
}
