#!/bin/bash

FIREWALL_AGENT_NAME=firewall_agent-firewall-agent-1
CORE_NAME=core-core-1
REVERSE_PROXY_AGENT_KEYWORD="reverse-proxy-agent"

echo "timestamp,firewall_agent_cpu,firewall_agent_mem,core_cpu,core_mem,reverse_proxy_agent_cpu,reverse_proxy_agent_mem"
echo "timestamp,firewall_agent_cpu,firewall_agent_mem,core_cpu,core_mem,reverse_proxy_agent_cpu,reverse_proxy_agent_mem" >> monitor.log

while true; do
  timestamp=$(date +%s)

  # 只抓一次 stats
  stats=$(docker stats --no-stream --format '{{.Name}},{{.CPUPerc}},{{.MemUsage}}')
  fw_stats=$(echo "$stats" | grep "$FIREWALL_AGENT_NAME" | awk -F',' '{print $2 "," $3}' | awk -F'[ %,/]' '{print $1"%,"$2$3}')
  fw_cpu=$(echo $fw_stats | cut -d',' -f1)
  fw_mem=$(echo $fw_stats | cut -d',' -f2)

  core_stats=$(echo "$stats" | grep "$CORE_NAME" | awk -F',' '{print $2 "," $3}' | awk -F'[ %,/]' '{print $1"%,"$2$3}')
  core_cpu=$(echo $core_stats | cut -d',' -f1)
  core_mem=$(echo $core_stats | cut -d',' -f2)

  # 3. Reverse Proxy Agent (process)
  pid=$(pgrep -fl "$REVERSE_PROXY_AGENT_KEYWORD" | head -n 1 | awk '{print $1}')
  if [ -z "$pid" ]; then
    rp_cpu="N/A"
    rp_mem="N/A"
  else
    rp_cpu=$(ps -p $pid -o %cpu= | awk '{printf "%.2f%%", $1}')
    rp_mem=$(ps -p $pid -o rss= | awk '{printf "%.2fMiB", $1/1024}')
  fi

  echo "$timestamp,$fw_cpu,$fw_mem,$core_cpu,$core_mem,$rp_cpu,$rp_mem"
  echo "$timestamp,$fw_cpu,$fw_mem,$core_cpu,$core_mem,$rp_cpu,$rp_mem" >> monitor.log
  # sleep 5
done

