'''
Created by Morgan Habecker
Usage: python3 shodan_tool.py -k <API_KEY> -d <DOMAIN> -o <OUTPUT_MODE> -p <PREFIX>
'''

import shodan, json, argparse, ipaddress

def is_ip_address(address):
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def process_host(api, entry, output_mode, prefix, all_hosts_data):
    try:
        if is_ip_address(entry):
            host = api.host(entry)
        else:
            host = api.search("hostname:" + entry)

        formatted_host = json.dumps(host, indent=4)

        if output_mode in ["single", "mix"]:
            filename = f"{prefix}_{entry}.json"
            with open(filename, "w") as host_file:
                host_file.write(formatted_host)

        if output_mode in ["combo", "mix"]:
            all_hosts_data.append(host)

    except shodan.APIError as e:
        print(f"Error with {entry}: {e}")

def main(args):
    api = shodan.Shodan(args.key)
    all_hosts_data = []

    if args.domain:
        process_host(api, args.domain, args.output, args.prefix, all_hosts_data)
    elif args.ip:
        process_host(api, args.ip, args.output, args.prefix, all_hosts_data)
    elif args.list:
        try:
            with open(args.list, 'r') as file:
                entries = file.read().splitlines()
            for entry in entries:
                process_host(api, entry, args.output, args.prefix, all_hosts_data)
        except FileNotFoundError:
            print("The specified hosts file does not exist.")
            return

    if args.output in ["combo", "mix"]:
        combo_filename = f"{args.prefix}_combined_hosts.json"
        with open(combo_filename, "w") as combined_file:
            combined_file.write(json.dumps(all_hosts_data, indent=4))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Shodan Host Information Retrieval Tool (S.H.I.R.T.)")
    parser.add_argument("-d", "--domain", help="Single domain search")
    parser.add_argument("-i", "--ip", help="Single IP search")
    parser.add_argument("-l", "--list", help="File containing list of hosts (FQDN and/or IP)")
    parser.add_argument("-k", "--key", required=True, help="Shodan API key")
    parser.add_argument("-o", "--output", choices=["combo", "single", "mix"], default="combo", help="Output mode: combo, single, or mix")
    parser.add_argument("-p", "--prefix", default="shirt", help="Output file name prefix")

    args = parser.parse_args()

    main(args)
