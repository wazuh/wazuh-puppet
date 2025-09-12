# Copyright (C) 2015, Wazuh Inc.
# Define an ossec command
define wazuh::command (
  $command_name,
  $command_executable,
  $command_expect  = 'srcip',
  $timeout_allowed = true,
  $target_arg      = 'manager_ossec.conf',
) {
  require wazuh::params_manager

  if ($timeout_allowed) { $command_timeout_allowed='yes' } else { $command_timeout_allowed='no' }
  concat::fragment { $name:
    target  => $target_arg,
    order   => 46,
    content => template('wazuh/fragments/_command.erb'),
  }
}
