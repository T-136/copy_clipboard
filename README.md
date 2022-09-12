# Copy Clipboard

a cli that allows sending one's clipboard to someone else

## Installation

### Prerequisites

cargo & rust are required, as there are no prebuilt binaries.

### Compilation

```bash
cargo build --release
cd target/release
```

## Starting the server

```bash
./server
```

## Creating your private key

```bash
./client generate-key
```

Alternatively you can use

```bash
./client generate-key --userConfigDir --keyFile <name>
# Shorthand:
./client generate-key -u -k <name>
```

(for generating a key with a different name in the default config dir)

or

```bash
./client generate-key --keyFile <path>
# Shorthand:
./client generate-key -k <path>
```

for generating a key with a different name.

## Recovering your public key

The previous step should print out your public key, but in case you forgot you can recover it with

```bash
./client get-public-key # default key
./client get-public-key -u -k <name> # key with name in user config dir
./client get-public-key -k <path> # key at path
```

depending on the path you created your key in

## Sending your clipboard to someone else

You can send your clipboard using

```bash
./client send <target-public-key>
```

## Recieving a clipboard sent for you

You can receieve a clipboard sent for you with

```bash
./client receive # default key
./client receive -u -k <name> # key with name in user config dir
./client receive -k <path> # key at path
```

depending on the path to the private key of the public key your sender used.

View the commands with `--help` for further options.
