class { 'wazuh::repo':
}
class { "wazuh::agent":
wazuh_register_endpoint => "localhost",
wazuh_reporting_endpoint => "localhost"
}