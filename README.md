# sekey.sh

A shell script for managing SSH keypairs stored in Apple Secure Enclave. Inspired by
[SeKey](https://github.com/sekey/sekey).

_Disclosure: I operate the coding agent to produce this program._

Worked on:

- macOS 26 and newer.
- MacBook with TouchID (tested on MacBook Pro M1 Pro).

## Installation

Take the [sekey.sh](./sekey.sh) and run it on your terminal. You can put its location in `$PATH` to
run it anywhere without the full path.

After created the keypairs, we must add the identities to current SSH agent for authentication, by
this command: `./sekey.sh -a`.

## Usage

Run `./sekey.sh -h` to see how to use it. This script works similar to
[SeKey](https://github.com/sekey/sekey).

Create the keypair with a memorizable label:

```
./sekey.sh -c <label>
```

List the created keypairs:

```
./sekey.sh -l
```

Example list output, here we have 2 keypair already generated:

```
Hash: F4FE56............................37E833
Label: ssh__test_sekey
Fingerprint: SHA256:SsTE9P...............................fM7tGs

Hash: B19DF0............................425DF4
Label: ssh__test_sekey_1
Fingerprint: SHA256:ItzOCx...............................2nEf3U
```

Export the public key for adding to the remote host:

```
./sekey.sh -e <hash>
```

Example public key output:

```
sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBIJ6j+dlYUoEo+pn3dAzwZsHWzAhHME1hBDbWAyVjEKn72A5wIlqcGcyzXY3fsIU8yv7HH/3HQUzcwuJez6+A2oAAAAEc3NoOg== ssh:
```

Add the identities to SSH agent, so that we can do authentication via Secure Enclave:

```
./sekey.sh -a
```

Delete a keypair:

```
./sekey.sh -d <hash>
```

## References

**sekey.sh** is heavily inspired by [SeKey](https://github.com/sekey/sekey). I hoped its author
continue the work so that I didn't need to write this script. The implementation could not exist
without great information from
[arianvp](https://gist.github.com/arianvp/5f59f1783e3eaf1a2d4cd8e952bb4acf) and
[gatezh](https://gatezh.com/posts/macos-secure-enclave-ssh-keys/).

Thank you for the great works.

## License

[Unlicense](https://unlicense.org/) - public domain.
