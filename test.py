import requests
import json
import time
import os
import logging

PREFIX = "Biforch_"

def read_existing_config(config_path):
    if os.path.exists(config_path):
        with open(config_path, "r") as f:
            return f.read()
    return ""

def update_nginx_config():
    # key + secret from downloaded apikey.txt
    api_key = "7beKiNep5x7bS8G4Wjqb1G3Sk/6uMs+yH1J9p58cGJSUOf5zGW8qloEcfT4AqR9YMMGASP3Sn0l5Y7gc"
    api_secret = "S8kU5NcxtFkBuAl2PcNv8C+luxsg1CaukIT/uQGU1VGMhf4b0C0ticcRZrsRcDfJSQ7T7ZEghkdpy8E/"

    # Define the basics, hostname to use
    remote_uri = "http://192.168.87.1"

    # Get firewall rules
    r = requests.get(
        f"{remote_uri}/api/firewall/filter/search_rule",
        auth=(api_key, api_secret),
    )
    rules = r.json()

    # Initialize Nginx config storage
    nginx_config = {"memos": [], "openspeedtest": []}

    # Process rules
    for row in rules["rows"]:
        if row["enabled"] != "1":
            continue
        
        rule_detail = requests.get(
            f"{remote_uri}/api/firewall/filter/get_rule/{row['uuid']}",
            auth=(api_key, api_secret),
        ).json()["rule"]
        
        action = next(action for action, details in rule_detail["action"].items() if details['selected'] == 1)
        source_net = rule_detail["source_net"]
        destination_net = rule_detail["destination_net"]
        
        if not destination_net.startswith(PREFIX):
            continue
        else:
            destination_net = destination_net[len(PREFIX):]
        
        nginx_rule = f"{'allow' if action == 'pass' else 'deny'} {source_net};"
        
        if destination_net in nginx_config:
            nginx_config[destination_net].append(nginx_rule)

    logging.debug(f"Generated Nginx config: {nginx_config}")
    nginx_reloaded = False
    
    # Generate Nginx configuration output
    for service, rules in nginx_config.items():
        config_path = f"./nginx/auto.d/{service}.conf"
        new_config = "\n".join(rules) if rules else "allow all;"
        
        existing_config = read_existing_config(config_path)
        
        if new_config != existing_config:
            with open(config_path, "w") as f:
                f.write(new_config + "\n")
            nginx_reloaded = True
    
    # Reload Nginx only if configuration changed
    if nginx_reloaded:
        os.system("nginx -s reload")

# Run the update function every second
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    while True:
        update_nginx_config()
        time.sleep(1)
