import os
import re
from jinja2 import Environment, FileSystemLoader


def cert(crt_folder_address):
    crt_dict = {}
    regex = r"(?P<u_name>\w+).crt"
    crt_regex = r"-+BEGIN CERTIFICATE-+\s(?P<crt>.+?)\s-+END CERTIFICATE-+"
    crt_list = [os.path.join(crt_folder_address, f) for f in os.listdir(crt_folder_address)]
    for file in crt_list:
        user_name = re.search(regex, file).group("u_name")
        with open(file, "r") as f:
            user_crt = re.search(crt_regex, f.read(), re.DOTALL).group("crt")
            crt_dict[user_name] = [user_crt]
    return crt_dict


def key(key_folder_address):
    key_dict = {}
    filename_regex = r"(?P<u_name>\w+)\.key"
    key_regex = r"-+BEGIN PRIVATE KEY-+\s(?P<key>.+?)\s-+END PRIVATE KEY-+"
    key_list = [os.path.join(key_folder_address, f) for f in os.listdir(key_folder_address)]
    for file in key_list:
        filename = re.search(filename_regex, file).group("u_name")
        with open(file) as f:
            user_key = re.search(key_regex, f.read(), re.DOTALL).group("key")
            key_dict[filename] = user_key
    return key_dict


def existing_files_check(ovpn_folder):
    name_list = []
    created_list = [f for f in os.listdir(ovpn_folder)]
    filename_regex = r"(?P<u_name>\w+)\.ovpn"
    for name in created_list:
        only_name = re.search(filename_regex, name).group("u_name")
        name_list.append(only_name)
    return name_list


def get_crt_key_dict(crt_folder_address, key_folder_address, ovpn_folder):
    crt_dict = cert(crt_folder_address)
    key_dict = key(key_folder_address)
    for filename, user_key in key_dict.items():
        crt_dict[filename].append(user_key)

    existing_files_list = existing_files_check(ovpn_folder)
    for name in existing_files_list:
        if name in crt_dict.keys():
            del crt_dict[name]
    return crt_dict


def ca_ta_add(ca_folder_address, ta_folder_address):
    ca_regex = r"-+BEGIN CERTIFICATE-+\s(?P<crt>.+?)\s-+END CERTIFICATE-+"
    ta_regex = r"-+BEGIN OpenVPN Static key V1-+\s(?P<key>.+?)\s-+END OpenVPN Static key V1-+"
    with open(ca_folder_address, "r") as f:
        ca_cer = re.search(ca_regex, f.read(), re.DOTALL).group("crt")
    with open(ta_folder_address, "r") as f:
        ta_key = re.search(ta_regex, f.read(), re.DOTALL).group("key")
    return ca_cer, ta_key


def generate_config(ovpn_folder, crt_dict, ca_path, ta_path):
    ca_cer, ta_key = ca_ta_add(ca_path, ta_path)
    env = Environment(loader=FileSystemLoader("."))
    templ = env.get_template("ovpn_template.txt")
    for filename, (user_crt, user_key) in crt_dict.items():
        config = {"user_cert": user_crt, "user_key": user_key, "ca": ca_cer, "ta": ta_key}
        userovpn = os.path.join(ovpn_folder, filename + '.ovpn')
        with open(userovpn, "w") as wf:
            wf.write(templ.render(config))


def main():
    cer_folder_address = "/home/localadmin/easy-rsa/pki/issued/"
    keys_folder_address = "/home/localadmin/easy-rsa/pki/private/"
    ovpn_path = "/home/localadmin/ovpn/"
    crt_dict = get_crt_key_dict(cer_folder_address, keys_folder_address, ovpn_path)

    ca_path = "/home/localadmin/key/ca.crt"
    ta_path = "/home/localadmin/key/ta.key"
    generate_config(ovpn_path, crt_dict, ca_path, ta_path)


if __name__ == "__main__":
    main()
