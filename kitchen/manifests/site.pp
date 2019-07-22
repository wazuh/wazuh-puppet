#node '75e919b02929' {
#  include wazuh::manager
#}
node '423f16b82cc2' {
  class { "wazuh::manager":
        configure_wodle_openscap => false
  }
}
node '39fd3683b00a' {
  class { "wazuh::agent":
        ossec_ip => "10.1.0.16",
        configure_wodle_openscap => false
  }
}
