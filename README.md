# OCaml ssh-agent

An ssh-agent protocol implementation in OCaml.

This library offers [angstrom](https://github.com/inhabitedtype/angstrom/)/[faraday](github.com/inhabitedtype/faraday/) parsers/serializers for the ssh agent protocol as well as some helper functions for implementing an ssh-agent.
In the `cmd/` directory you find two simple example applications:

- `ssh_add`: this application connects to `$SSH_AUTH_SOCK`, generates a private key (rsa or ed25519 are supported), adds it to the ssh-agent and exits.
  Note that it doesn't save the public key anywhere or removes it from the agent, and is only good for polluting your ssh-agent with random keys.
  You may want to write the public key to a file and then remove it from the agent using `ssh-add -d path-to-key.pub`.

- `ssh_agent_server`: this application listens on a socket `ocaml-ssh-agent.sock` in CWD, and implements a very basic ssh-agent.
  It supports adding keys, removing keys and signing using rsa or ed25519 keys.
  It does not support concurrent connections and is not suitable for Production Use™.

These applications are not built by default.
To build or run them using dune you must do so manually:
```sh
$ dune build cmd/ssh_add.exe cmd/ssh_agent_server.exe # to build
$ dune exec -- cmd/ssh_add.exe --help # to run ssh_add
$ dune exec -- cmd/ssh_agent_server.exe # to run ssh_agent_server
```

For the Qubes OS unikernel using this library see [qubes-mirage-ssh-agent](https://github.com/reynir/qubes-mirage-ssh-agent).
