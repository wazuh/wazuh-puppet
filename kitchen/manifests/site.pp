node 'manager00_ubuntu' {
  class { "wazuh::manager":
        configure_wodle_openscap => false
  }
}
node 'agent00_ubuntu' {
  class { "wazuh::agent":
        wazuh_register_endpoint => "10.1.0.39",
        wazuh_reporting_endpoint => "10.1.0.39",
        configure_wodle_openscap => false
  }
}
node 'manager00_centos' {
  class { "wazuh::manager":
        configure_wodle_openscap => true
  }
}
node 'agent00_centos' {
  class { "wazuh::agent":
        wazuh_register_endpoint => "10.1.0.41",
        configure_wodle_openscap => true
  }
}
