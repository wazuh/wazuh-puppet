#Define for a specific ossec active-response
define wazuh::activeresponse(
  $command_name,
  $ar_location           = 'local',
  $ar_level              = 7,
  $ar_rules_id           = [],
  $ar_timeout            = 300,
  $ar_repeated_offenders = '',
) {
  require wazuh::params

  concat::fragment { $name:
    target  => $wazuh::params::config_file,
    order   => 55,
    content => template('ossec/activeresponse.erb')
  }
}
