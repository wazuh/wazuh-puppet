rpm -Uvh https://yum.puppet.com/puppet7-release-el-8.noarch.rpm
yum -y install puppetserver
ln -s /opt/puppetlabs/bin/puppet /bin
ln -s /opt/puppetlabs/server/bin/puppetserver /bin
echo "[main]" | sudo tee -a /etc/puppetlabs/puppet/puppet.conf > /dev/null
echo "server = "$HOSTNAME | sudo tee -a /etc/puppetlabs/puppet/puppet.conf > /dev/null
echo "dns_alt_names = "$HOSTNAME | sudo tee -a /etc/puppetlabs/puppet/puppet.conf > /dev/null
echo "127.0.0.1 puppet" | sudo tee -a /etc/hosts > /dev/null
cat /etc/puppetlabs/puppet/puppet.conf
systemctl start puppetserver
systemctl enable puppetserver
systemctl status puppetserver
puppet module install /tmp/wazuh-wazuh-${{ env.VERSION }}.tar.gz
hostname=$(sudo puppetserver ca list --all | awk '{if(NR>1)print $1;}')
echo "127.0.0.1 "$hostname | sudo tee -a /etc/hosts > /dev/null
echo "node "\"$hostname\"" {" | sudo tee -a /etc/puppetlabs/code/environments/production/manifests/stack.pp  > /dev/null
echo "class {'wazuh::manager':} ->  class {'wazuh::indexer':} -> class {'wazuh::filebeat_oss':} -> class {'wazuh::dashboard':}" | sudo tee -a /etc/puppetlabs/code/environments/production/manifests/stack.pp > /dev/null
echo "}" | sudo tee -a /etc/puppetlabs/code/environments/production/manifests/stack.pp > /dev/null
cat /etc/puppetlabs/code/environments/production/manifests/stack.pp
bash -c 'puppet agent -tod || test $? -eq 2'