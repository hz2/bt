# BitTorrent Client

## Design

- design of this client is based on the [BitTorrent v1.0 protocol](https://wiki.theory.org/BitTorrentSpecification).
- the client is written in Rust and only uses core `stdlib` for networking, i.e. no [`tokio`](https://docs.rs/tokio/latest/tokio/) or [`async`](https://doc.rust-lang.org/std/keyword.async.html)
  - this was for a personal challenge to handle any asynchronous I/O using only `stdlib`

## Verifying a sample download

I got the torrent from Debian's official site which can be found [here](https://cdimage.debian.org/debian-cd/current/arm64/bt-cd/).
Note that what lies in the `current` directory is the latest version of Debian, which at the time of writing is `12.10.0`.
Also note that the list of peers that the tracker returns for this torrent are mostly IPv6 addresses, so the client
may not work as expected if you don't have IPv6 support on your network.

The page includes the following:

- `SHA256SUMS`
- `SHA256SUMS.sign`
- `SHA512SUMS`
- `SHA512SUMS.sign`
- `debian-12.10.0-arm64-netinst.iso.torrent`

To download all the files (you don't need to as you can eyeball the hash), you can use the following command:

```bash
wget https://cdimage.debian.org/debian-cd/current/arm64/bt-cd/SHA256SUMS \
     https://cdimage.debian.org/debian-cd/current/arm64/bt-cd/SHA256SUMS.sign \
     https://cdimage.debian.org/debian-cd/current/arm64/bt-cd/SHA512SUMS \
     https://cdimage.debian.org/debian-cd/current/arm64/bt-cd/SHA512SUMS.sign \
     https://cdimage.debian.org/debian-cd/current/arm64/bt-cd/debian-12.10.0-arm64-netinst.iso.torrent
```

If you downloaded a file, assuming it is named `debian-12.10.0-arm64-netinst.iso`, you can verify the hash of both
the `*.torrent` and `*.iso` files (assuming they're all in the same directory) using the following command:

```bash
sha512sum -c SHA512SUMS
```

which should output something like:

```text
debian-12.10.0-arm64-netinst.iso: OK
debian-12.10.0-arm64-netinst.iso.torrent: OK
```
