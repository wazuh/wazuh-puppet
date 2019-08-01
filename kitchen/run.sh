#!/bin/bash

# Adding Wazuh module from Puppet forge.

LIBRARIAN_OUTPUT="$(librarian-puppet show)"

if [[ $LIBRARIAN_OUTPUT == *"wazuh"* ]]; then
	echo "Librarian-Puppet: Wazuh module already installed .. Continue"
else
	echo "Installing Wazuh module"
	librarian-puppet install

        sed -i "s/'Debian', 'debian'/&, 'Ubuntu', 'ubuntu'/" modules/wazuh/manifests/manager.pp
        sed -i "s/'Debian', 'debian'/&, 'Ubuntu', 'ubuntu'/" modules/wazuh/manifests/agent.pp
fi


echo "Deleting Old logs, old instances files, etc ..."
rm -rf .kitchen/logs/* # removing old logs
rm -rf .kitchen/def* # removing old .yml files associated for old kitchen instances
rm -rf ./manifests/se* # removing all temporal manifests files.

echo "Kitchen is destroying old instances ..."
kitchen destroy all # destroying all existing kitchen instances

echo "Docker is stopping old containers of they do exist"
docker stop $(docker ps -a -q)

echo "Docker is deleting the stopped containers"
docker rm $(docker ps -a -q)

echo "Kitchen is creating the new instances"
kitchen create # creating new kitchen instances

echo "Getting Wazuh managers IPs to the agents"
ubuntu_manager_ip="$(docker inspect --format '{{ .NetworkSettings.IPAddress }}' `docker ps | awk '{print $NF}' | grep  ubuntu | grep manager`)"
centos_manager_ip="$(docker inspect --format '{{ .NetworkSettings.IPAddress }}' `docker ps | awk '{print $NF}' | grep  centos | grep manager`)"

echo "getting a copy of ./manifests/site.pp.template"
cp ./manifests/site.pp.template ./manifests/site.pp

echo "Assigning Wazuh managers IPs to the corresponding agents."
sed -i 's/ubuntu_manager_ip/'${ubuntu_manager_ip}'/g' ./manifests/site.pp
sed -i 's/centos_manager_ip/'${centos_manager_ip}'/g' ./manifests/site.pp

echo "Kitchen is converging ..."
kitchen converge

echo "Kitchen is testing ..."
kitchen verify
