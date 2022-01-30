import os
import re
from jinja2 import Environment, FileSystemLoader

# TODO написать реализацию скрипта с cli интерфейсом


cer_folder_address = "C:/repos/mrdobriykot/open_vpn/crt"
keys_folder_address = "C:/repos/mrdobriykot/open_vpn/key"
ovpn_path = "C:/repos/mrdobriykot/open_vpn/ovpn"
ca_path = "C:/repos/mrdobriykot/open_vpn/ca/ca.crt"
ta_path = "C:/repos/mrdobriykot/open_vpn/ta/ta.key"
crt_dict = {}
gen_files = []
name_list = []
ca_ta = [] # ca.crt and tls-auth.key


def cert(crt_folder_address):
    regex = r"CN=(?P<u_name>\w+)/"
    crt_regex = r"-+BEGIN CERTIFICATE-+\s(?P<crt>.+?)\s-+END CERTIFICATE-+"
    crt_list = [os.path.join(crt_folder_address, f) for f in os.listdir(crt_folder_address)]
    for file in crt_list:
        with open(file) as f:
            user_name = re.search(regex, f.read()).group("u_name")
        with open(file) as f:
            user_crt = re.search(crt_regex, f.read(), re.DOTALL).group("crt")
            crt_dict[user_name] = [user_crt]


def key(key_folder_address):
    filename_regex = r"(?P<u_name>\w+)\.key"
    key_regex = r"-+BEGIN PRIVATE KEY-+\s(?P<key>.+?)\s-+END PRIVATE KEY-+"
    key_list = [os.path.join(key_folder_address, f) for f in os.listdir(key_folder_address)]
    for file in key_list:
        filename = re.search(filename_regex, file).group("u_name")
        with open(file) as f:
            user_key = re.search(key_regex, f.read(), re.DOTALL).group("key")
            crt_dict[filename].append(user_key)


def ca_ta_add(ca_folder_address, ta_folder_address):
    ca_regex = r"-+BEGIN CERTIFICATE-+\s(?P<crt>.+?)\s-+END CERTIFICATE-+"
    ta_regex = r"-+BEGIN OpenVPN Static key V1-+\s(?P<key>.+?)\s-+END OpenVPN Static key V1-+"
    with open(ca_folder_address, "r") as f:
        ca_cer = re.search(ca_regex, f.read(), re.DOTALL).group("crt")
    with open(ta_folder_address, "r") as f:
        ta_key = re.search(ta_regex, f.read(), re.DOTALL).group("key")
    ca_ta.append(ca_cer)
    ca_ta.append(ta_key)


def file_check(ovpn_folder):
    created_list = [f for f in os.listdir(ovpn_folder)]
    filename_regex = r"(?P<u_name>\w+)\.ovpn"
    for name in created_list:
        only_name = re.search(filename_regex, name).group("u_name")
        name_list.append(only_name)
    for name in name_list:
        if name in crt_dict.keys():
            del crt_dict[name]


def generate_config(ovpn_folder):
    if not ovpn_folder.endswith("/"):
        ovpn_folder = ovpn_folder + "/"
    env = Environment(loader=FileSystemLoader("."))
    templ = env.get_template("ovpn_template1.txt")
    for keys, values in crt_dict.items():
        config = {"user_cert": values[0], "user_key": values[1], "ca": ca_ta[0], "tls": ca_ta[1]}
        userovpn = ovpn_folder + keys + '.ovpn'
        with open(userovpn, "w") as wf:
            wf.write(templ.render(config))


def main():
    cert(cer_folder_address)
    key(keys_folder_address)
    ca_ta_add(ca_path, ta_path)
    file_check(ovpn_path)
    generate_config(ovpn_path)


if __name__ == "__main__":
    main()
