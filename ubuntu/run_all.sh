docker network create \
  --subnet=172.18.0.0/16 \
  my_custom_network
docker run -d --net my_custom_network --ip 172.18.0.100 --name ssh-server ssh-sandbox
docker run -d --net my_custom_network -v /Users/morinop/windtunnel/sandbox:/home/sandbox -p 9000:9000 -p 9001:9001 ubuntu22-mcp-from-local