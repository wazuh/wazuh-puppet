class wazuh::params_elastic {

  case $::kernel {
      'Linux': {
        $elasticsearch_service = 'elasticsearch'
        $elasticsearch_package = 'elasticsearch'
        $config_owner = 'elasticsearch'
        $config_group = 'elasticsearch'
        $config_mode = '0640'

        $elasticsearch_cluster_name = 'es-wazuh'
        $elasticsearch_node_name = 'es-node-01'
        $elasticsearch_node_master = 'true'
        $elasticsearch_node_data = 'true'
        $elasticsearch_node_ingest = 'true'
        $elasticsearch_node_max_local_storage_nodes = '1'
        
        $elasticsearch_path_data = "/var/lib/elasticsearch"
        $elasticsearch_path_logs = "/var/log/elasticsearch"


        $elasticsearch_ip = 'YOUR_ELASTICSEARCH_IP'
        $elastcisearch_port = 9200
        $elasticsearch_discovery_option = 'discovery.type: single-node'
        $elasticsearch_cluster_initial_master_nodes = "#cluster.initial_master_nodes: ['es-node-01']"

      }
  }
}
