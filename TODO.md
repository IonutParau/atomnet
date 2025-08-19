# For future release

- WiFi-like stuff

# For MVP

- DNS over RCPS
- OSP, ordered stream protocol
- AWP over OSP
- anpm, oppm-like package managet built with AtomNET and AWP

## OSP

`off` is used to order packets, `totalLen` is used to know when to flush.

```c
struct osp {
    uint32_t off;
    uint32_t totalLen;
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
