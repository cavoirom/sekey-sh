# Using SSH with Apple Secure Enclave

## Goals

* Generate SSH keypair with Secure Enclave.
* Store private key within SE, non-extractable.
* Add keys to default ssh-agent to use normally.

## Generate key

```
sc_auth create-ctk-identity \

```
```
        -l <keypair-label> \
        -t 'bio' \
        -k 'p-256-ne'

```

* -l <keypair-label>: give the key a label.
* -t 'bio': use Secure Enclave key type.
* -k 'p-256-ne': "ne" means non-exportable.

## List keys

```
# Default hash, can be used for deleting key.
sc_auth list-ctk-identities
# SHA256 hash.
sc_auth list-ctk-identities -t ssh

```

## Delete key

```
sc_auth delete-ctk-identity -h <Public Key Hash>

```

## Export public key

```
ssh-keygen -K -w /usr/lib/ssh-keychain.dylib -N "" -v

```

Note:
* Apple has a bug that it will override the next key to existing file. At least it will ask for confirmation, give us time to get the public key.
* The export order is top down.
* The key file is: id_ecdsa_sk_rk.pub.

## Add keys to ssh-agent

```
ssh-add -K -S /usr/lib/ssh-keychain.dylib

```

Usage: after add the keys to ssh-agent, we could use it as normal, ssh will ask for Touch ID when needed.

## References

[https://gist.github.com/arianvp/5f59f1783e3eaf1a2d4cd8e952bb4acf](https://gist.github.com/arianvp/5f59f1783e3eaf1a2d4cd8e952bb4acf)

[https://gatezh.com/posts/macos-secure-enclave-ssh-keys/](https://gatezh.com/posts/macos-secure-enclave-ssh-keys/)

[https://ewpratten.com/blog/ssh-secure-enclave](https://ewpratten.com/blog/ssh-secure-enclave)
