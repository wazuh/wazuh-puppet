# Wazuh App Copyright (C) 2020 Wazuh Inc. (License GPLv2)
# Opendistro configuration parameters
class wazuh::params_opendistro {
  $opendistro_service = 'elasticsearch'
  $opendistro_package = 'opendistroforelasticsearch'
  $config_owner = 'elasticsearch'
  $config_group = 'elasticsearch'
  $config_mode = '0640'

  $opendistro_cluster_name = 'es-wazuh'
  $opendistro_node_name = 'node-01'
  $opendistro_node_master = true
  $opendistro_node_data = true
  $opendistro_node_ingest = true
  $opendistro_node_max_local_storage_nodes = '1'

  $opendistro_path_data = '/var/lib/elasticsearch'
  $opendistro_path_logs = '/var/log/elasticsearch'


  $opendistro_ip = 'localhost'
  $elastcisearch_port = 9200
  $opendistro_discovery_option = 'discovery.type: single-node'
  $opendistro_cluster_initial_master_nodes = "#cluster.initial_master_nodes: ['es-node-01']"

}
