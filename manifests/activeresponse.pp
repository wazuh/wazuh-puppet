#Define for a specific ossec active-response
define wazuh::activeresponse(
  $command_name,
  $ar_location           = 'local',
  $ar_level              = 7,
  $ar_agent_id           = '',
  $ar_rules_id           = [],
  $ar_timeout            = 300,
  $ar_repeated_offenders = '',
) {

  require wazuh::params

  concat::fragment { $name:
    target  => 'ossec.conf',
    order   => 55,
    content => template('wazuh/fragments/_activeresponse.erb')
  }
}
