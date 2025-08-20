# For future release

- WiFi-like stuff

# For MVP

- OSP, ordered stream protocol
- AWP over OSP
- anpm, oppm-like package managet built with AtomNET and AWP

## OSP

`off` is used to order packets, `totalLen` is used to know when to flush.

```c
struct osp {
    uint32_t totalLen;
    uint32_t off;
    uint16_t len;
    uint8_t data[len];
}
```

## AWP

Super basic HTTP-like

```c
struct awp_header {
    char name[]; // newline-terminated, so it can be read with read("l")
    char body[]; // newline-terminated, so it can be read with read("l")
};

struct awp_request {
    char header[] = "AWP\0";
    uint8_t majorVersion;
    uint8_t minorVersion;
    awp_header headers[]; // terminated by header with an empty name and body
    uint32_t bodySize;
    uint8_t body[bodySize];
};

struct awp_response {
    uint16_t responseCode;
    awp_header headers[]; // terminated by header with an empty name and body
    uint32_t bodySize;
    uint8_t body[bodySize];
};
```

## DNS (conceptually)

The idea is that given a string `google.com`, the DNS daemon will check if it has it in the hosts. If not, it'll scan through the listed subservers and
check if there is a suffix that matches (say `.com`), and if so respond with the IP. Then the client can ask the other DNS server for that host name.
A catch-all fallback may also be supplied. Groups of servers may be used for load balancing, where a random one is picked.

Obviously, these would automatically check RCPS certificate authorities for public keys to ensure this is safe, and have an option to *enforce* that every
DNS server in the chain has a public key used to ensure maximum security E2EE. Maximum number of "hops" should also be an option.

This would allow a robust DNS with all the good stuff.

If multiple DNS servers are used by an AtomNET node, then it should try them in order and use the first result. This is basically a 2nd chain.
It is more for having backup DNS servers than any kind of extra security, similar to the reasoning behind multiple certificate authorities in RCPS.
