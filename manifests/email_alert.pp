# Wazuh App Copyright (C) 2018 Wazuh Inc. (License GPLv2)
# Define an email alert
define wazuh::email_alert(
  $alert_email,
  $alert_group = false
) {
  require wazuh::params_manager

  concat::fragment { $name:
    target  => 'ossec.conf',
    order   => 66,
    content => template('wazuh/email_alert.erb'),
  }
}
