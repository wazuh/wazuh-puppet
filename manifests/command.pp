# Define an ossec command
define wazuh::command(
  $command_name,
  $command_executable,
  $command_expect = 'srcip',
  $timeout_allowed = true,
) {
  require wazuh::params

  if ($timeout_allowed) { $command_timeout_allowed='yes' } else { $command_timeout_allowed='no' }
  concat::fragment { $name:
    target  => 'ossec.conf',
    order   => 45,
    content => template('wazuh/command.erb'),
  }
}
