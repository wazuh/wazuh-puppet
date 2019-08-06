#!/bin/bash

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
