$discovery_type = 'single-node'
stage { 'certificates': }
stage { 'repo': }
stage { 'indexerdeploy': }
stage { 'securityadmin': }
stage { 'dashboard': }
stage { 'manager': }
Stage[certificates] -> Stage[repo] -> Stage[indexerdeploy] -> Stage[securityadmin] -> Stage[manager] -> Stage[dashboard]
class { 'wazuh::certificates':
  indexer_certs => [['node-1','127.0.0.1']],
  manager_certs => [['master','127.0.0.1']],
  dashboard_certs => ['127.0.0.1'],
  stage => certificates,
}
class { 'wazuh::repo':
stage => repo,
}
class { 'wazuh::indexer':
  stage => indexerdeploy,
}
class { 'wazuh::securityadmin':
stage => securityadmin
}
class { 'wazuh::manager':
  stage => manager,
}
class { 'wazuh::filebeat_oss':
  stage => manager,
}
class { 'wazuh::dashboard':
  stage => dashboard,
}