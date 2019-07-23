#!/bin/bash

kitchen destroy all
kitchen create
manager_ip="$(docker inspect --format '{{ .NetworkSettings.IPAddress }}' `docker ps | awk '{print $NF}' | grep  manager`)"
sed -i 's/manager_ip/'${manager_ip}'/g' ./manifests/site.pp
kitchen converge
kitchen verify
sed -i 's/'${manager_ip}/'manager_ip/g' ./manifests/site.pp
