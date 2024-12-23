class wazuh_indexer {
  include install_product
  include modify_config_file

  $indexer_node_name = 'node1'
  $indexer_ip = 'localhost',
  $indexer_port = '9200',
  $indexer_discovery_hosts = [], # Empty array for single-node configuration
  $indexer_cluster_initial_master_nodes = ['node-1'],
  $indexer_cluster_CN = ['node-1'],

  install_product { 'wazuh-indexer':
    package_name    => 'wazuh-indexer',
    desired_version => '5.0.0',
  }

  # Configure specific files for Wazuh Indexer
  modify_config_file {
    config_file = '/car/ossec/etc/ossec.conf',
    config_lines = [],
    file_type = 'yaml'
  }

  service { 'wazuh-indexer':
    ensure => running,
    enable => true,
  }
}
