# Isabelle's Lazy Message Protocol

### network packet protocol

I don't know whether or not this is a super practical way of doing things
but i'm lazy and it seems to work so gonna roll with it lol

| segment size | usage                               |
|--------------|-------------------------------------|
| 1 byte       | u8 signifies the type of packet     |
| 8 byte       | u64 length of the packet contents   |
| 32 byte      | SHA256 packet contents checksum     |
| `u64::MAX`   | packet contents                     |