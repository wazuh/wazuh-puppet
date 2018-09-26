# Wazuh App Copyright (C) 2018 Wazuh Inc. (License GPLv2)
# Define an ossec command
define wazuh::command(
  String $command_name,
  String $command_executable,
  String $command_expect = 'srcip',
  Integer $command_order = 45,
  Enum['yes', 'no'] $command_timeout_allowed = 'yes',
) {
  # Build command fragment
  concat::fragment { "ossec.conf_command-${title}":
    target  => 'ossec.conf',
    order   => $command_order,
    content => template('wazuh/fragments/_command.erb'),
  }
}
