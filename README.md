Authors:
Niek van Noort, Erik Dekker

# TLS1.3-KeyShare-Covert-Channel
This project implements a covert channel in the TLS key exchange by using the Key Share extension. The data is hidden as fake public keys inside the TLS ClientHello.

We will first illustrate how to send a simple string over the covert channel from command line,

At the server:
```
sudo python3 CovertServer.py -b example.com -p 443 --encrypt -t
```

At the client:
```
python3 CovertClient.py -s example.com -p 443 --encrypt -g x25519 -t "Hi there!"
```

The server will receive the message "Hi there!" and will print it to stdout.


# Tunneling

For measurement purposes this covert channel can listen to traffic going over a specific interface named 'tlsc'. All this traffic will be tunneled from the covert channel client to the covert channel server. A python script is added to setup this interface on the client and server.

At the client:
```
sudo python3 setup.py client 10.0.0.1/24
```

At the server:
```
sudo python3 setup.py server 10.0.0.2/24
```

These changes can be undone by:
```
sudo python3 setup.py client clean
sudo python3 setup.py server clean
```

Then the server should be started as follows (the argument to -b can also be an IP address):
```
sudo python3 CovertServer.py -b example.com -p 443 --encrypt
```

Then the client should be started as follows:
```
sudo python3 CovertClient.py -s example.com -p 443 --encrypt -g x25519 -g x448 -g ffdhe2048 -g ffdhe3072 -g ffdhe4096 -g ffdhe6144 -g ffdhe8192
```

The covert channel can then be tested using netcat,

server:
```
netcat -u -l 10.0.0.2 5000
```

client:
```
netcat -u 10.0.0.2 5000
Hi there!
```

The message "Hi there!" should appear at the netcat server if everything works properly.


We measured the best throughput with the groups x25519, x448, ffdhe2048, ffdhe3072, ffdhe4096, ffdhe6144 and ffdhe8192 (12.3 Mbit/s with encryption, 14.2 Mbit/s without encryption on a 1 Gbit/s direct link). However, in this case we always sent enough data to completely fill each ClientHello with the maximum amount of data. The maximum amount is the sum of all the groups data sizes minus 1, because 1 byte is used to specify fragmentation or padding. 

| Group     | Data Size (Bytes) |
|-----------|-----------|
| x25519    | 32        |
| x448      | 56        |
| P-256     | 32        |
| P-384     | 48        |
| P-521     | 65        |
| ffdhe2048 | 256       |
| ffdhe3072 | 384       |
| ffdhe4096 | 512       |
| ffdhe6144 | 768       |
| ffdhe8192 | 1024      |


By also adding the groups P-256, P-384 and P-521, you can increase the number of bytes that can be sent in one ClientHello. However, more calculations need to be done to transform a random byte sequence into a valid public key for these groups. These calculation cause bad throughput.


# Use the covert channel within python

Here is an example on how to use the covert channel in python,

server:
```
from CovertServer import CovertServer

cs = CovertServer("127.0.0.1", 12345, encrypt=True)
data = cs.recv()
print(data.decode('UTF-8'))
```

client:
```
from CovertClient import CovertClient
from TLSValues import SUPPORTED_GROUP_X25519, SUPPORTED_GROUP_X448

cc = CovertClient("127.0.0.1", 12345, encrypt=True, groups=[SUPPORTED_GROUP_X25519, SUPPORTED_GROUP_X448])
msg = "Hello!!!"
cc.send(bytes(msg, 'UTF-8'))
```
