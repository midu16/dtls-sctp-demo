# DTLS over SCTP demo

- Building the golang server and client:

```bash
go mod tidy &&     CGO_ENABLED=0 go build -o server ^Cserver &&     CGO_ENABLED=0 go build -o client ./client
```
- Running the example code:

Open Terminal-1:

```bash
./client/client -server=localhost:4444
```

Open Terminal-2:

```bash
./server/server
```

Optional, open Terminal-3:

```bash
sudo tcpdump -i lo -w dtls-sctp-demo.pcap
```

!Note, that the tcpdump requires to be pre-installed from your rpm-manager. An example of the dtls-sctp-demo.pcap its provided in the repo.


