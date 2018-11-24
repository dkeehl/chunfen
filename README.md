## Chunfen

An encrypted network tunnel,
built upon [tokio](https://github.com/tokio-rs/tokio)
and [ring](https://github.com/briansmith/ring).

### System Requirements

You need a version of rust that supports edition 2018.
Statable and nightly versions are both ok.

It donesn't have any system specific code itself,
so it should work on any platform that tokio and ring support.

Tested on windows.

### Usage

To compile, run `cargo build --release`. Then it generates two excutable
files, a `client` and a `server`.

#### The server

    ./server -b BindIP -p Port -k SecretKey

Note that the secret key must be longer than 10.

#### The client

    ./client -s ServerAddress:Port -b BindIP -p ListeningPort -k SecretKey

The client runs as a local socks5 proxy. Parameters `-b` and `-p` are
optional. It listens on `127.0.0.1:1080` by default.

### Project layout

The crates included as part of Chunfen are:

* [`chunfen_socks`]: A socks5 library.
It can also be built as an standalone socks5 server.

* [`chunfen_sec`]: The encryption layer. It's a **very limited** subset
of TLS protocol. The interface design is inspired by
[rustls](https://github.com/ctz/rustls).

### About the name

Chunfen(春分) in Chinese means the Spring Equinox.
