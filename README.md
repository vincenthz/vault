Vault
=====

Vault is a utility to store secrets (words, password, file) securely.

Usage
-----

Initialize:

    $ vault init

Store a new secret:

    $ vault create

Read a secret:

    $ vault read <name>

List all known secrets:

    $ vault list

The security design
-------------------

Vault is using a symetric key on disk (~/.vault/key) to encrypt and decrypt secrets.
If this key is leaked, then anyone could have access to the secrets. It is recommended
to use a key passphrase during initialization.

Each secret is stored on disk AES encrypted using an ESSIV-like chain blocking mode.
