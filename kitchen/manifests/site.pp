#node '75e919b02929' {
#  include wazuh::manager
#}
node 'manager00_ubuntu' {
  class { "wazuh::manager":
        configure_wodle_openscap => false
  }
}
node 'agent00_ubuntu' {
  class { "wazuh::agent":
        ossec_ip => "manager_ip",
        configure_wodle_openscap => false
  }
}
