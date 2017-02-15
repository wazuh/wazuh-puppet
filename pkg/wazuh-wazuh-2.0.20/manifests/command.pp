# Define an ossec command
define ossec::command(
  $command_name,
  $command_executable,
  $command_expect = 'srcip',
  $timeout_allowed = true,
) {
  require ossec::params

  if ($timeout_allowed) { $command_timeout_allowed='yes' } else { $command_timeout_allowed='no' }
  concat::fragment { $name:
    target  => $ossec::params::config_file,
    order   => 45,
    content => template('ossec/command.erb'),
  }
}
