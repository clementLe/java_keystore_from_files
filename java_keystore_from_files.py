#!/usr/bin/python
# -*- coding: utf-8 -*-

# Original Source: https://github.com/ansible-collections/community.general/blob/main/plugins/modules/system/java_keystore.py
# What's new:
#   - Original module takes the content of private key and certificate => This module takes paths. It allows to avoid the creation of temp files (with bad permissions)
#   - Removing the .p12 file at the end or in case of trouble
#   - Adding the ability to configure a keystore with a protected private key (private_key_passphrase)

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: java_keystore
short_description: Create or delete a Java keystore in JKS format.
description:
     - Create or delete a Java keystore in JKS format for a given certificate.
options:
    name:
        description:
          - Name of the certificate.
        required: true
    certificate_path:
        description:
          - Absolute path of the certificate that should be used to create the key store.
          - File must be present on the remote server
        required: true
    private_key_path:
        description:
          - Absolute path of the private key that should be used to create the key store.
          - File must be present on the remote server
        required: true
    private_key_passphrase:
        description:
          - Private key passphrase needed if your private key is protected
          - This password will be used to protect the key inside the keystore
        required: false
    password:
        description:
          - Password that should be used to secure the key store.
        required: true
    dest:
        description:
          - Absolute path where the jks should be generated.
        required: true
    owner:
        description:
          - Name of the user that should own jks file.
        required: false
    group:
        description:
          - Name of the group that should own jks file.
        required: false
    mode:
        description:
          - Mode the file should be.
        required: false
    force:
        description:
          - Key store will be created even if it already exists.
        required: false
        type: bool
        default: 'no'
requirements: [openssl, keytool]
'''

EXAMPLES = '''
# Create a key store for the given certificate (inline)
- java_keystore:
    name: example
    certificate_path: /etc/pki/tls/certs/my_server.crt
    private_key: /etc/pki/tls/private/my_server.key
    password: changeit
    dest: /etc/security/keystore.jks
    mode: "0600"
'''

RETURN = '''
msg:
  description: Output from stdout of keytool/openssl command after execution of given command or an error.
  returned: changed and failure
  type: str
  sample: "Unable to find the current certificate fingerprint in ..."

rc:
  description: keytool/openssl command execution return value
  returned: changed and failure
  type: int
  sample: "0"

cmd:
  description: Executed command to get action done
  returned: changed and failure
  type: str
  sample: "openssl x509 -noout -in /tmp/cert.crt -fingerprint -sha256"
'''


from ansible.module_utils.basic import AnsibleModule
import os
import re


def read_certificate_fingerprint(module, openssl_bin, certificate_path):
    current_certificate_fingerprint_cmd = "%s x509 -noout -in %s -fingerprint -sha256" % (openssl_bin, certificate_path)
    (rc, current_certificate_fingerprint_out, current_certificate_fingerprint_err) = run_commands(module, current_certificate_fingerprint_cmd)
    if rc != 0:
        return module.fail_json(msg=current_certificate_fingerprint_out,
                                err=current_certificate_fingerprint_err,
                                rc=rc,
                                cmd=current_certificate_fingerprint_cmd)

    current_certificate_match = re.search(r"=([\w:]+)", current_certificate_fingerprint_out)
    if not current_certificate_match:
        return module.fail_json(
            msg="Unable to find the current certificate fingerprint in %s" % current_certificate_fingerprint_out,
            rc=rc,
            cmd=current_certificate_fingerprint_err
        )

    return current_certificate_match.group(1)


def read_stored_certificate_fingerprint(module, keytool_bin, alias, keystore_path, keystore_password):
    stored_certificate_fingerprint_cmd = "%s -list -alias '%s' -keystore '%s' -storepass '%s' -v" % (keytool_bin, alias, keystore_path, keystore_password)
    (rc, stored_certificate_fingerprint_out, stored_certificate_fingerprint_err) = run_commands(module, stored_certificate_fingerprint_cmd)
    if rc != 0:
        if "keytool error: java.lang.Exception: Alias <%s> does not exist" % alias not in stored_certificate_fingerprint_out:
            return module.fail_json(msg=stored_certificate_fingerprint_out,
                                    err=stored_certificate_fingerprint_err,
                                    rc=rc,
                                    cmd=stored_certificate_fingerprint_cmd)
        else:
            return None
    else:
        stored_certificate_match = re.search(r"SHA256: ([\w:]+)", stored_certificate_fingerprint_out)
        if not stored_certificate_match:
            return module.fail_json(
                msg="Unable to find the stored certificate fingerprint in %s" % stored_certificate_fingerprint_out,
                rc=rc,
                cmd=stored_certificate_fingerprint_cmd
            )

        return stored_certificate_match.group(1)


def run_commands(module, cmd, check_rc=True):
    return module.run_command(cmd, check_rc)


def cert_changed(module, openssl_bin, keytool_bin, keystore_path, keystore_pass, alias, certificate_path):
    current_certificate_fingerprint = read_certificate_fingerprint(module, openssl_bin, certificate_path)
    stored_certificate_fingerprint = read_stored_certificate_fingerprint(module, keytool_bin, alias, keystore_path, keystore_pass)
    return current_certificate_fingerprint != stored_certificate_fingerprint


def create_jks(module, name, openssl_bin, keytool_bin, keystore_path, password, certificate_path, private_key_path, keypass):
    if module.check_mode:
        module.exit_json(changed=True)
    else:
        keystore_p12_path = "/tmp/keystore.p12"
        try:
            if os.path.exists(keystore_path):
                os.remove(keystore_path)

            if os.path.exists(keystore_p12_path):
                os.remove(keystore_p12_path)

            passin = ""
            # when keypass is provided
            if keypass:
                passin = "-passin 'pass:%s'" % keypass

            export_p12_cmd = "%s pkcs12 -export -name '%s' -in '%s' -inkey '%s' -out '%s' -passout 'pass:%s' %s" % (
                openssl_bin, name, certificate_path, private_key_path, keystore_p12_path, password, passin)
            (rc, export_p12_out, export_p12_err) = run_commands(module, export_p12_cmd)
            if rc != 0:
                return module.fail_json(msg=export_p12_out,
                                        rc=rc,
                                        cmd=export_p12_cmd)

            import_keystore_cmd = "%s -importkeystore " \
                                  "-destkeystore '%s' " \
                                  "-destkeypass '%s' " \
                                  "-srckeystore '%s' " \
                                  "-srcstoretype pkcs12 " \
                                  "-alias '%s' " \
                                  "-deststorepass '%s' " \
                                  "-srcstorepass '%s' " \
                                  "-noprompt" % (keytool_bin, keystore_path, keypass, keystore_p12_path, name, password, password)
            (rc, import_keystore_out, import_keystore_err) = run_commands(module, import_keystore_cmd)
            if rc == 0:
                update_jks_perm(module, keystore_path)
                return module.exit_json(changed=True,
                                        msg=import_keystore_out,
                                        rc=rc,
                                        cmd=import_keystore_cmd,
                                        stdout_lines=import_keystore_out)
            else:
                return module.fail_json(msg=import_keystore_out,
                                        rc=rc,
                                        cmd=import_keystore_cmd)
        finally:
            os.remove(keystore_p12_path)


def update_jks_perm(module, keystore_path):
    module.params['path'] = keystore_path
    file_args = module.load_file_common_arguments(module.params)
    module.set_fs_attributes_if_different(file_args, False)


def process_jks(module):
    name = module.params['name']
    password = module.params['password']
    keystore_path = module.params['dest']
    force = module.params['force']
    openssl_bin = module.get_bin_path('openssl', True)
    keytool_bin = module.get_bin_path('keytool', True)
    certificate_path = module.params['certificate_path']
    private_key_path = module.params['private_key_path']
    keypass = module.params['private_key_passphrase']

    if not os.path.exists(certificate_path):
        return module.fail_json(
            msg="Unable to find the certificate file %s" % certificate_path,
            rc=1,
            cmd="None"
        )
    if not os.path.exists(private_key_path):
        return module.fail_json(
            msg="Unable to find the certificate file %s" % private_key_path,
            rc=1,
            cmd="None"
        )

    if os.path.exists(keystore_path):
        if force:
            create_jks(module, name, openssl_bin, keytool_bin, keystore_path, password, certificate_path, private_key_path, keypass)
        else:
            if cert_changed(module, openssl_bin, keytool_bin, keystore_path, password, name, certificate_path):
                create_jks(module, name, openssl_bin, keytool_bin, keystore_path, password, certificate_path, private_key_path, keypass)
            else:
                if not module.check_mode:
                    update_jks_perm(module, keystore_path)
                return module.exit_json(changed=False)
    else:
        create_jks(module, name, openssl_bin, keytool_bin, keystore_path, password, certificate_path, private_key_path, keypass)


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        self.add_file_common_args = True
        argument_spec = dict(
            name=dict(required=True),
            certificate_path=dict(required=True),
            private_key_path=dict(required=True),
            private_key_passphrase=dict(required=False, no_log=True, type='str'),
            password=dict(required=True, no_log=True),
            dest=dict(required=True),
            force=dict(required=False, default=False, type='bool')
        )
        self.argument_spec = argument_spec


def main():
    spec = ArgumentSpec()
    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        add_file_common_args=spec.add_file_common_args,
        supports_check_mode=spec.supports_check_mode
    )
    process_jks(module)


if __name__ == '__main__':
    main()
