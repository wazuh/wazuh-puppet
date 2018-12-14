#Define for a specific ossec cluster
define wazuh::cluster(
  $cl_name,
  $cl_node_name = 'node01',
  $cl_node_type = 'master',
  $cl_key       = '',
  $cl_port      = '1516',
  $cl_bin_addr  = '0.0.0.0',
  $cl_node      = ['NODE_IP','NODE_IP2'],
  $cl_hidden    = 'no',
  $cl_disabled  = 'yes',
) {

  require wazuh::params

  concat::fragment { $name:
    target  => 'ossec.conf',
    order   => 95,
    content => template('wazuh/fragments/_cluster.erb')
  }
}
