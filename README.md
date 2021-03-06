# java_keystore_from_files
Ansible Module to create keystore from a certificate and private key files

## Description

This modules is inspired by [java_keystore Ansible module](https://github.com/ansible-collections/community.general/blob/main/plugins/modules/system/java_keystore.py).
It has been modify to implement these updates:
- Original module takes the content of private key and certificate => This module takes paths. It allows to avoid the creation of temp files (with bad permissions)
- Removing the .p12 file at the end or in case of trouble
- Adding the ability to configure a keystore with a protected private key (private_key_passphrase)

## Usage

```yaml
---
module: java_keystore_from_files
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
```

## Example

```yaml
# Create a key store for the given certificate
- java_keystore_from_files:
    name: example
    certificate_path: /etc/pki/tls/certs/my_server.crt
    private_key_path: /etc/pki/tls/private/my_server.key
    password: "changeit"
    dest: /etc/security/keystore.jks
    mode: "0600"

# Create a key store for the given certificate with a passphrase protected key
- java_keystore_from_files:
    name: example
    certificate_path: /etc/pki/tls/certs/my_server.crt
    private_key_path: /etc/pki/tls/private/my_server.key
    private_key_passphrase: "my_key_passphrase"
    password: "changeit"
    dest: /etc/security/keystore.jks
    mode: "0600"
```

## Return
```yaml
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
```
