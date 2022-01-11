# Wazuh App Copyright (C) 2021 Wazuh Inc. (License GPLv2)
# Opendistro configuration parameters
class wazuh::params_opendistro {
  $wazuh-indexer_service = 'wazuh-indexer'
  $wazuh-indexer_package = 'wazuh-indexer'
  $config_owner = 'wazuh-indexer'
  $config_group = 'wazuh-indexer'
  $config_mode = '0640'

  $wazuh-indexer_cluster_name = 'es-wazuh'
  $wazuh-indexer_node_name = 'node-01'
  $wazuh-indexer_node_master = true
  $wazuh-indexer_node_data = true
  $wazuh-indexer_node_ingest = true
  $wazuh-indexer_node_max_local_storage_nodes = '1'

  $wazuh-indexer_path_data = '/var/lib/wazuh-indexer'
  $wazuh-indexer_path_logs = '/var/log/wazuh-indexer'


  $wazuh-indexer_ip = 'localhost'
  $elastcisearch_port = 9200
  $wazuh-indexer_discovery_option = 'discovery.type: single-node'
  $wazuh-indexer_cluster_initial_master_nodes = "#cluster.initial_master_nodes: ['es-node-01']"

}
