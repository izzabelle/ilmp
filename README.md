# Isabelle's Lazy Message Protocol

### network packet protocol

I don't know whether or not this is a super practical way of doing things
but I'm lazy and it seems to work so gonna roll with it lol

| segment size | usage                                      |
|--------------|--------------------------------------------|
| 1 byte       | u8 packet kind                             |
| 1 byte       | u8 encrypt flag                            |
| 8 byte       | u64 length of the packet contents          |
| 4 byte       | CRC32 packet contents checksum             |
| 32 byte      | SHA256 packet contents integrity check     |
| `u64::MAX`   | packet contents                            |

### packet kind

packet kind has defined values for packets but leaves many open for user defined packets to be added to the protocol

| byte        | packet kind                                          |
| ----------- | ---------------------------------------------------- |
| `0x00`      | message - a simple text packet                       |
| `0x01-0xfc` | valid for custom packet usage                        |
| `0xfd`      | leave - announces a disconnect                       |
| `0xfe`      | join - announces a new connection                    |
| `0xff`      | agreement - used to help generate an agreed upon key |

### encrypt flag

encrypt flag can be `0x00` for no encrypt or `0xff` for ring AEAD symmetric encrypt


