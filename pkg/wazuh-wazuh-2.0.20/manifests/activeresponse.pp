#Define for a specific ossec active-response
define ossec::activeresponse(
  $command_name,
  $ar_location           = 'local',
  $ar_level              = 7,
  $ar_rules_id           = [],
  $ar_timeout            = 300,
  $ar_repeated_offenders = '',
) {
  require ossec::params

  concat::fragment { $name:
    target  => $ossec::params::config_file,
    order   => 55,
    content => template('ossec/activeresponse.erb')
  }
}