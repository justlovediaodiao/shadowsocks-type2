# shadowsocks-type2 protocol

The original shadowsocks protocol see [Protocol](https://shadowsocks.org/en/spec/Protocol.html) and [AEAD Ciphers](https://shadowsocks.org/en/spec/AEAD-Ciphers.html).

## tcp

```
[nonce][padding][encrypted payload]
```

- nonce: same with shadowsocks protocol. 
- padding: 16~32 byte data
- encrypted payload: 

```
[timestamp][target address][payload]
```

- timestamp: 4 byte timestamp.
- target address: same with shadowsocks protocol. 
- payload: same with shadowsocks protocol. 

### padding

length: sum every byte of hash value and calculate the remainder divided by 16. Then Add 16 to get the padding length.

```
length = sum(HMAC(sha256, nonce, key)) % 16 + 16
```

- key: the same key which is used to encrypt payload.

value: the first length bytes of nonce.

```
HMAC(sha256, nonce, key)[0:length]
```

### timestamp

a 4 byte uint value of current unix timestamp. It must be within two minutes of the system time.


## udp

same as tcp.