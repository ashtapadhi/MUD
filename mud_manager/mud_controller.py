from urllib.request import urlopen
from urllib.error import URLError, HTTPError
from subprocess import call
import dns.resolver
import sys
import os
import json
import glob


dir_input = "/Users/asv/Documents/iptabless/mud_manager/"
mud_file_store = dir_input+'mud.json'
CA = dir_input+'cert.pem'
protocols = "protocol_mapping.json"
protocol_map={}
in_acl_policies = []
out_acl_policies = []
def resolve_domain_advanced(domain):
    try:
        # Resolve to all IPv4 addresses
        answers = dns.resolver.resolve(domain, 'A')
        ip_addresses = [str(rdata) for rdata in answers]
        return ip_addresses
    except dns.resolver.NXDOMAIN:
        return f"Domain {domain} does not exist"
    except dns.resolver.NoAnswer:
        return f"No A records found for {domain}"
    except Exception as e:
        return f"Error resolving {domain}: {e}"

def generate_iptables_rule(type, ip, protocol, port_no, action):
    """
    Generates an iptables rule based on input parameters.

    Args:
        source_ip (str): Source IP address or subnet.
        protocol (str): Protocol (e.g., 'tcp', 'udp', or 'all').
        port_no (int or str): Port number. Use "all" for no specific port.
        action (str): Action to take (e.g., 'ACCEPT', 'DROP', 'REJECT').

    Returns:
        str: The generated iptables rule as a string.
    """
    # Validate the action
    valid_actions = ['ACCEPT', 'DROP', 'REJECT']
    if action.upper() not in valid_actions:
        raise ValueError(f"Invalid action: {action}. Must be one of {valid_actions}.")

    # Validate the protocol
    valid_protocols = ['tcp', 'udp', 'icmp', 'all']
    if protocol.lower() not in valid_protocols:
        raise ValueError(f"Invalid protocol: {protocol}. Must be one of {valid_protocols}.")

    if type not in ['source', 'destination']:
        raise ValueError("Invalid IP type. It should be either 'source' or 'destination'.")

    # Base rule
    rule = f"iptables -A INPUT -p {protocol.lower()}"
   
    # Add source IP or destination IP
    if type == 'source':
        
        rule += f" -s {ip}"
    elif type == 'destination':
        rule += f" -d {ip}"

    # Add port if specified
    if port_no != "all" and isinstance(port_no, int):
        rule += f" --dport {port_no}"

    # Add the action
    rule += f" -j {action.upper()}"
    print(rule)
    return rule

def generate_flow_table_rule(table_id, match_type, ip, protocol, port_no, action):
    """
    Generates a flow table rule for a Software Defined Networking (SDN) environment.

    Args:
        table_id (int): The table ID in the flow table.
        match_type (str): Match type ('source' or 'destination').
        ip (str): IP address or subnet to match.
        protocol (str): Protocol (e.g., 'tcp', 'udp', or 'all').
        port_no (int or str): Port number. Use "all" for no specific port.
        action (str): Action to take (e.g., 'forward', 'drop', 'controller').

    Returns:
        str: The generated flow table rule as a string.
    """
    # Validate the action
    valid_actions = ['forward', 'drop', 'controller']
    if action.lower() not in valid_actions:
        raise ValueError(f"Invalid action: {action}. Must be one of {valid_actions}.")

    # Validate the protocol
    valid_protocols = ['tcp', 'udp', 'icmp', 'all']
    if protocol.lower() not in valid_protocols:
        raise ValueError(f"Invalid protocol: {protocol}. Must be one of {valid_protocols}.")

    if match_type not in ['source', 'destination']:
        raise ValueError("Invalid match type. It should be either 'source' or 'destination'.")

    # Base rule
    rule = f"table={table_id},priority=100,"

    # Add match for IP and protocol
    if match_type == 'source':
        rule += f"ip_src={ip},"
    elif match_type == 'destination':
        rule += f"ip_dst={ip},"

    if protocol.lower() != "all":
        rule += f"nw_proto={protocol.lower()},"

    # Add match for port
    if port_no != "all" and isinstance(port_no, int):
        if match_type == 'source':
            rule += f"tp_src={port_no},"
        elif match_type == 'destination':
            rule += f"tp_dst={port_no},"

    # Add action
    if action.lower() == "forward":
        rule += "actions=output:1"
    elif action.lower() == "drop":
        rule += "actions=drop"
    elif action.lower() == "controller":
        rule += "actions=CONTROLLER"

    print(rule)
    return rule

def load_protocol_mappings(file_path):
    """
    Load protocol mappings from a JSON file.
    :param file_path: Path to the JSON file containing protocol mappings
    :return: A dictionary with protocol numbers as keys and names as values
    """
    global protocol_map
    try:
        with open(file_path, "r") as file:
            protocol_map = json.load(file)
            #print(protocol_map)
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return {}
    except json.JSONDecodeError:
        print("Error: Invalid JSON format in the file.")
        return {}

def get_protocol_name(protocol_number):
    """
    Get the protocol name for a given number.
    :param protocol_number: The protocol number to search for
    :param protocol_map: Dictionary of protocol mappings
    :return: Protocol name or error message
    """
    global protocol_map
    #print(protocol_map)
    return protocol_map.get(str(protocol_number), f"Unknown protocol number: {protocol_number}")

def dlfile(device_json, device_ps7):
    # Open the url
    # device_json for json file form mudserver
    # device_ps7 for getting signed signature
    
        #print(protocol_map)
    #if not protocol_map:
        #print("No protocol mappings available. Exiting.")
        #return
    try:
        #print("before")
        f1 = urlopen(device_json)
        #print("here")
        device_name = device_json.split("mud/", 1)[1]
        
        if device_name.endswith(".json"):
            #print("and here")
            device_json_path = dir_input+device_name
            # writing json file
            with open(device_json_path, "wb") as local_file:
                local_file.write(f1.read())
            device_name_ps7_format = device_json.split("mud/", 1)[1]
            device_name_ps7_format = os.path.splitext(
                device_name_ps7_format)[0]
            device_name_ps7 = dir_input+device_name_ps7_format+".p7s"
            f2 = urlopen(device_ps7)
            # writing signature file
            #print("6",device_name_ps7)
            with open(device_name_ps7, "wb") as local_file:
                local_file.write(f2.read())

        else:
            device_json_path = dir_input+device_name
            device_json_format = device_json.split("mud/", 1)[1]+".json"
            # writing json file
            with open(device_json_path, "wb") as local_file:
                local_file.write(f1.read())
            f2 = urlopen(device_ps7)
            device_name_ps7_format = device_ps7.split("mud/", 1)[1][:-1]
            device_name_ps7 = dir_input+device_name_ps7_format
            #print("6",device_name_ps7)
            # writing signature file
            with open(device_name_ps7, "wb") as local_file:
                local_file.write(f2.read())
        # calling openssl command
        decrypted = call(['openssl', 'cms', '-verify', '-in', device_name_ps7, '-CAfile',
                         CA, '-out', mud_file_store, '-inform', 'DER', '-content', device_json_path])
        # delete(device_name) # remove old download files
    # handle errors
    except HTTPError as e:
        print(("HTTP Error:", e.code, device_json, device_ps7))
    except URLError as e:
        print(("URL Error:", e.reason, device_json, device_ps7))


def delete(device_name_del):
    filename = device_name_del
    search_trace = [filename+'.p7s', filename+'.json']
    file_list = []
    for root, dirs, files in os.walk(dir_input):
        for trace in search_trace:
            search_trace_path = os.path.join(root, trace)
            for filename in glob.glob(search_trace_path):
                if os.path.exists(filename):
                    file_list.append(filename)
                else:
                    print(('No files path found' + filename))
    for device_file in file_list:
        os.remove(device_file)


def radius():
    if (str(sys.argv[2]) == "W"):
        device_url = str(sys.argv[1])  # print url
        device_json = device_url
        if device_json.endswith(".json"):
            device_url_ps7 = device_url
            device_url_ps7 = device_url_ps7.split(".json", 1)[0]
            #print("1",device_url_ps7)
            device_name_ps7 = device_url_ps7.split("mud/", 1)[1]
            #print("2",device_name_ps7)
            device_name_ps7_format = os.path.splitext(device_name_ps7)[0]
            #print("3",device_name_ps7_format)
            device_ps7 = device_url_ps7+".p7s"
            #print("4",device_ps7)

        else:
            device_ps7 = device_url+".p7s/"
        dlfile(device_json, device_ps7)


def get_json_value(json_object, index, protocol_no=None):
    try:
        with open(mud_file_store, 'r') as f:
            data = f.read()
    except IOError:
        print(('cannot open file to read', mud_file_store))
    else:
        data = json.loads(data)
    in_acl = (data['ietf-access-control-list:access-lists']['acl'][1]['aces']['ace'])
    len_in_acl = len(data['ietf-access-control-list:access-lists']['acl'][1]['aces']['ace'])
    #print(len_in_acl)
    out_acl = (data['ietf-access-control-list:access-lists']['acl'][0]['aces']['ace'])
    len_out_acl = len(data['ietf-access-control-list:access-lists']['acl'][0]['aces']['ace'])
    #print(len_out_acl)
    last_update = data['ietf-mud:mud']['last-update']
    cache_validity = data['ietf-mud:mud']['cache-validity']
    new_list = []
    if protocol_no:
        protocol_name=str(get_protocol_name(protocol_no).lower())

    if json_object=="in_len":
        new_list+=[len_in_acl] 
    elif json_object=="out_len":
        new_list+=[len_out_acl]


    for row in in_acl:
        try:
            if json_object == "acl_name_in":
                mylist = ((data['ietf-access-control-list:access-lists']['acl'][1]['name']))
                #print(mylist)
                new_list += [mylist]
            if json_object == "acl_type_in":
                mylist = ((data['ietf-access-control-list:access-lists']['acl'][1]['type']))
                new_list += [mylist]
            if json_object == "rule_name_in":
                mylist = ((row['name']))
                new_list += [mylist]
            if json_object == "src_dnsname_in":
                #print("source", (data['ietf-access-control-list:access-lists']['acl'][0]['matches']['ipv4']['ietf-acldns:src-dnsname']))
                #print(row['matches']['ipv4']['protocol'])
                mylist = ((row['matches']['ipv4']['ietf-acldns:src-dnsname']))
                new_list += [mylist]
            if json_object == "src_protocol_in":
                mylist = ((row['matches']['ipv4']['protocol']))
                new_list += [mylist]
            if json_object == "src_lower_port_in":
                #print("proto: ",protocol_name)
                mylist = ((row['matches'][protocol_name]['source-port']['port']))
                #print(mylist)
                new_list += [mylist]
           # if json_object == "src_upper_port_in":
           #     mylist = ((row['matches']['source-port-range']['upper-port']))
           #     new_list += [mylist]
            if json_object == "src_actions_in":
                mylist = ((row['actions']['forwarding']))
                new_list += [mylist]
        except KeyError:
            pass
    for row in out_acl:
        try:
            if json_object == "acl_name_out":
                mylist = ((data['ietf-access-control-list:access-lists']['acl'][0]['name']))
                new_list += [mylist]
            if json_object == "acl_type_out":
                mylist = ((data['ietf-access-control-list:access-lists']['acl'][0]['type']))
                new_list += [mylist]
            if json_object == "rule_name_out":
                mylist = ((row['name']))
                new_list += [mylist]
            if json_object == "src_dnsname_out":
                mylist = ((row['matches']['ipv4']['ietf-acldns:dst-dnsname']))
                new_list += [mylist]
            if json_object == "src_protocol_out":
                mylist = ((row['matches']['ipv4']['protocol']))
                new_list += [mylist]
            if json_object == "src_lower_port_out":
                mylist = ((row['matches'][protocol_name]['destination-port']['port']))
                new_list += [mylist]
            #if json_object == "src_upper_port_out":
             #   mylist = ((row['matches']['destination-port-range']['upper-port']))
              #  new_list += [mylist]
            if json_object == "src_actions_out":
                mylist = ((row['actions']['forwarding']))
                new_list += [mylist]
        except KeyError:
            pass
    #print("newlist",new_list)
    #print("index",index)
    if 'out'in json_object:
        if index < len_out_acl:
            try:
                return new_list[index]
            except ValueError:
                print("")
    else:
        if index < len_in_acl:
            try:
                return new_list[index]
            except ValueError:
                print("")



def read_json():
    '''# In_ACL
    acl_name_in = get_json_value("acl_name_in", 0)
    acl_type_in = get_json_value("acl_type_in", 0)
    rule_name_in = get_json_value("rule_name_in", 0)
    src_dnsname_in = get_json_value("src_dnsname_in", 0)
    src_protocol_in = get_json_value("src_protocol_in", 0)
    protocol_name=get_protocol_name(src_protocol_in).lower()
    #print(protocol_name.lower())
    src_lower_port_in = get_json_value("src_lower_port_in", 0,src_protocol_in)
    #print(src_lower_port_in)
    #src_upper_port_in = get_json_value("src_upper_port_in", 0)
    src_actions_in = get_json_value("src_actions_in", 0)
    # Out_ACL
    acl_name_out = get_json_value("acl_name_out", 0)
    acl_type_out = get_json_value("acl_type_out", 0)
    rule_name_out = get_json_value("rule_name_out", 0)
    src_dnsname_out = get_json_value("src_dnsname_out", 0)
    src_protocol_out = get_json_value("src_protocol_out", 0)
    protocol_name_out=get_protocol_name(src_protocol_out)
    #print(protocol_name_out)
    src_lower_port_out = get_json_value("src_lower_port_out", 0,src_protocol_out)
    #print(src_lower_port_out)
    #src_upper_port_out = get_json_value("src_upper_port_out", 0)
    src_actions_out = get_json_value("src_actions_out", 0)'''
    global in_acl_policies 
    global out_acl_policies 

    try:
        # Get the length of IN_ACL policies
        num_in_policies = get_json_value("in_len", 0)
        #print(num_in_policies)
        '''print(get_json_value("acl_name_in", 1))
        print(get_json_value("acl_type_in", 1))
        print(get_json_value("rule_name_in", 1))
        print(get_json_value("src_dnsname_in", 1))
        print(get_protocol_name(get_json_value("src_protocol_in", 1)).lower())
        print(get_json_value("src_lower_port_in", 1, get_json_value("src_protocol_in", 1)))
        print(get_json_value("src_actions_in", 1))'''
                
        #print("1st : ",policy_in)
        for i in range(5):
            proto_no= get_json_value("src_protocol_in", i)
            #print(proto_no)
            if proto_no==6 or proto_no==17:
                #print("inside loop")
                policy_in = {
                    "acl_name": get_json_value("acl_name_in", i),
                    "acl_type": get_json_value("acl_type_in", i),
                    "rule_name": get_json_value("rule_name_in", i),
                    "src_dnsname": get_json_value("src_dnsname_in", i),
                    "protocol": get_protocol_name(get_json_value("src_protocol_in", i)).lower(),
                    "port": get_json_value("src_lower_port_in", i, get_json_value("src_protocol_in", i)),
                    "action": get_json_value("src_actions_in", i)
                }
                #print(policy_in)
                in_acl_policies.append(policy_in)
                #print("OK")
            else:
                continue
        #print("OK")
        num_out_policies = get_json_value("out_len", 0)
        #print(num_out_policies)
        for i in range(5):
            proto_no= get_json_value("src_protocol_out", i)
            if proto_no==6 or proto_no==17:
                policy_out = {
                    "acl_name": get_json_value("acl_name_out", i),
                    "acl_type": get_json_value("acl_type_out", i),
                    "rule_name": get_json_value("rule_name_out", i),
                    "src_dnsname": get_json_value("src_dnsname_out", i),
                    "protocol": get_protocol_name(get_json_value("src_protocol_out", i)).lower(),
                    "port": get_json_value("src_lower_port_out", i, get_json_value("src_protocol_out", i)),
                    "action": get_json_value("src_actions_out", i)
                }
                out_acl_policies.append(policy_out)
            else:
                continue

        #return in_acl_policies, out_acl_policies
    except Exception as e:
        print(f"Error processing JSON data: {e}")
        return [], []

    def dacl_ip_in():
        if (src_dnsname_in == "attacker"):  # dnsname to ip
            ip_address_in = "172.19.155.54"
            return ip_address_in
        elif(src_dnsname_in == "bldmng"):  # dnsname to ip
            ip_address_in = "172.19.155.146"
            return ip_address_in
        src_dnsname_in = dacl_ip_in()

    def dacl_ip_out():
        if (src_dnsname_out == "attacker"):  # dnsname to ip
            ip_address_out = "172.19.155.54"
            return ip_address_out
        elif(src_dnsname_out == "bldmng"):
            ip_address_out = "172.19.155.146"
            return ip_address_out
        src_dnsname_out = dacl_ip_out()

    # permit udp host 172.19.155.106 any eq 5000
    # Egress Point
    # Out_ACL
    def egress_acl_1():  # Read from file to create ACL formate
        '''print("IN_ACL Policies:")
        print(in_acl_policies)

        print("\nOUT_ACL Policies:")
        print(out_acl_policies)'''
        for i in range(5):

            #generate_iptables_rule("destination",resolve_domain_advanced(out_acl_policies[i]['src_dnsname'])[0], out_acl_policies[i]['protocol'],out_acl_policies[i]['port'] , out_acl_policies[i]['action'])
            generate_flow_table_rule(i,"destination",resolve_domain_advanced(out_acl_policies[i]['src_dnsname'])[0], out_acl_policies[i]['protocol'],out_acl_policies[i]['port'] , "forward")
        #print(src_actions_out)  # permit / deny
        #print(get_protocol_name(src_protocol_in))  # protocol
        #print("host")  # per user ACL src = any
        #print(resolve_domain_advanced(src_dnsname_out))  # destination
        #print("any ")  # port match any
        #print(src_lower_port_out)
       
    # Ingress Point
    #'permit ip any host 172.19.155.106'
    # IN_ACL

    def ingress_acl_1():  # Read from file to create ACL formate
        
        for i in range(5):

            #generate_iptables_rule("source",resolve_domain_advanced(in_acl_policies[i]['src_dnsname'])[0], in_acl_policies[i]['protocol'],in_acl_policies[i]['port'] , in_acl_policies[i]['action'])
            generate_flow_table_rule(i,"source",resolve_domain_advanced(in_acl_policies[i]['src_dnsname'])[0], in_acl_policies[i]['protocol'],in_acl_policies[i]['port'] , "forward")
        #print(src_actions_in)  # permit / deny
        #print(get_protocol_name(src_protocol_out))  # protocol
        #print("any host")  # per user ACL src = any
        #print(resolve_domain_advanced(src_dnsname_in)[0])  # destination
        #print("range")  # port match any
        #print(src_lower_port_in)
       

    def egress_acl_permit():
        print("iptables -A OUTPUT -j ACCEPT")

    def egress_acl_deny():
        print("iptables -A OUTPUT -j DROP")

    def egress_acl_null():
        print('')
    load_protocol_mappings(protocols)
        #print(protocol_map)
    if not protocol_map:
        print("No protocol mappings available. Exiting.")
        return
    if (str(sys.argv[2]) == "R1"):
        ingress_acl_1()
    elif(str(sys.argv[2]) == "R2"):
        egress_acl_1()
    elif(str(sys.argv[2]) == "R3"):
        egress_acl_deny()
    # Get only USER NAMER fro DACL to verify second request from SWITCH after access - accept
    if (str(sys.argv[2]) == "U1"):  # Read from file to send DACL user name for ingress
        print(acl_name_in)  # DACL name with crypto key

    if (str(sys.argv[2]) == "U2"):  # Read from file to send DACL user name for egrees
        print(acl_name_out)  # DACL name with crypto key


if __name__ == '__main__':
    if len(sys.argv) > 1:
        a = str(sys.argv[1])  # Access through
    else:
        a = "null"
    load_protocol_mappings(protocols)
    radius()  # call json and signature verify program
    read_json()  # send the request