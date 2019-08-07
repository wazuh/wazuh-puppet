# Wazuh App Copyright (C) 2019 Wazuh Inc. (License GPLv2)
# Define an ossec command
define wazuh::command(
  $command_name,
  $command_executable,
  $command_expect = 'srcip',
  $timeout_allowed = true,
) {
  require wazuh::params_manager

  if ($timeout_allowed) { $command_timeout_allowed='yes' } else { $command_timeout_allowed='no' }
  concat::fragment { $name:
    target  => 'ossec.conf',
    order   => 46,
    content => template('wazuh/fragments/_command.erb'),
  }
}
