# Assignment 3: Transport Layer

#### Overview
In this assignment, you will be implementing a simple TCP (STCP) protocol on top of our custom socket interface MYSOCK.  Here, STCP and MYSOCK will run on top of a **reliable** network, so you do not need to worry about dropped packets, reordering, retransmissions and timeouts.  Additionally, the socket and network interfaces have already been implemented for you so you only have to implement STCP in `transport.c`.

**Note:** This assignment will only compile in a Linux or Solaris environment. Please use the provided Multipass VMs, CS ugrad/masters machines, or your own Linux/WSL system.

## STCP Specification

#### Overview
STCP is a full duplex, connection oriented transport layer that guarantees in-order delivery. Full duplex means that data flows in both directions over the same connection. Guaranteed delivery means that your protocol ensures that, short of catastrophic network failure, data sent by one host will be delivered to its peer in the correct order. Connection oriented means that the packets you send to the peer are in the context of some pre-existing state maintained by the transport layer on each host.

STCP treats application data as a stream. This means that no artificial boundaries are imposed on the data by the transport layer. If a host calls mywrite() twice with 256 bytes each time, and then the peer calls myread() with a buffer of 512 bytes, it will receive all 512 bytes of available data, not just the first 256 bytes. It is STCP's job to break up the data into packets and reassemble the data on the other side.

STCP labels one side of a connection active and the other end passive. Typically, the client is the active end of the connection and server the passive end. But this is just an artificial labeling; the same process can be active on one connection and passive on another (e.g., the HTTP proxy of Assignment#1 that "actively" opens a connection to a web server and "passively" listens for client connections).

The networking terms we use in the protocol specification have precise meanings in terms of STCP. Please refer to the glossary. 

#### STCP Packet Format
```
typedef uint32_t tcp_seq;

struct tcphdr {
        uint16_t th_sport;              /* source port */
        uint16_t th_dport;              /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgment number */
#ifdef _BIT_FIELDS_LTOH
        u_int   th_x2:4,                /* (unused) */
                th_off:4;               /* data offset */
#else
        u_int   th_off:4,               /* data offset */
                th_x2:4;                /* (unused) */
#endif
        uint8_t th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
        uint16_t th_win;                 /* window */
        uint16_t th_sum;                 /* checksum */
        uint16_t th_urp;                 /* urgent pointer */
        /* options follow */
};
typedef struct tcphdr STCPHeader;
```
For this assignment, you are not required to handle all fields in this header. Specifically, the provided network layer wrapper code sets th_sport, th_dport, and th_sum, while th_urp is unused; you may thus ignore these fields. Similarly, you are not required to handle all legal flags specified here: TH_RST, TH_PUSH, and TH_URG are ignored by STCP. The fields STCP uses are shown in the following table. Note that any relevant multi-byte fields of the STCP header will entail proper endianness handling with `htonl`/`ntohl` or `htons`/`ntohs`

The packet header field format (for the relevant fields) is as follows: 

|Field|Type|Description|
|-----|----|-----------|
|th_seq|tcp_seq|Sequence number associated with the packet|
|th_ack|tcp_seq|If this is an ACK packet, the sequence number being acknowledged by this packet. This may be included in any packet.|
|th_off|4 bits|The offset at which data begins in the packet.  For this assignment, you can assume that there is no optional data (20 bytes)|
|th_flags|uint8_t|Zero or more of the flags (TH_FIN, TH_SYN, etc.), or'ed together.|
|th_win|uint16_t|Advertised receiver window in bytes, i.e. the amount of outstanding data the host sending the packet is willing to accept. |

#### Sequence Numbers
STCP assigns sequence numbers to the streams of application data by numbering the bytes. The rules for sequence numbers are: 
- Sequence numbers sequentially number the SYN flag, FIN flag, and bytes of data, starting with a randomly chosen sequence number between 0 and 255, both inclusive. (The sequence numbers are exchanged using a 3-way SYN handshake in STCP as explained later). 
- Both SYN and FIN sequence numbers are associated with one byte of the sequence space which allows the sequence number acking mechanism to handle SYN and non-data bearing FIN packets despite the fact that there is no actual associated payload. 
- The sequence number should always be set in every packet. If the packet is a pure ACK packet (i.e., no data, and the SYN/FIN flags are unset), the sequence number should be set to the next unsent sequence number. 
- Initial sequence number can be choosen randomly

#### Data Packets
The following rules apply to STCP data packets: 
- The maximum payload size is 536 bytes. (you can use the global variable `STCP_MSS`)
- The `th_seq` field in the packet header contains the sequence number of the first byte in the payload.
- Data packets are sent as soon as data is available from the application. STCP performs no optimizations for grouping small amounts of data on the first transmission.

#### ACK Packets
In order to guarantee reliable delivery, data must be acknowledged. The rules for acknowledging data in STCP are: 
- Data is acknowledged by setting the ACK bit in the STCP packet header flags field. If this bit is set, then the th_ack field contains the sequence number of the next byte of data the receiver expects (i.e. one past the last byte of data already received). This is true no matter what data is being acknowledged, i.e. payload data, SYN, or FIN sequence numbers. The th_seq field should be set to the sequence number that would be associated with the next byte of data sent to the receiver.
- Acknowledgments are not delayed in STCP as they are in TCP. An acknowledgment should be sent as soon as data is received. 
- If a packet is received that contains duplicate data, a new acknowledgment should be sent for the current next expected sequence number. 

#### Sliding Window
There are two windows that you will have to take care of: the receiver and sender windows.

The receiver window is the range of sequence numbers which the receiver is willing to accept at any given instant. The window ensures that the transmitter does not send more data than the receiver can handle.

Like TCP, STCP uses a sliding window protocol. The transmitter sends data with a given sequence number up to the window limit. The window "slides" (increments in the sequence number space) when data has been acknowledged. The size of the sender window, which is equal to the other side's receiver window, indicates the maximum amount of data that can be "in flight" and unacknowledged at any instant, i.e. the difference between the last byte sent and the last byte ack'd.

**Rules for the Sliding Window:**
- The local receiver window and congestion window has a fixed size of 3072 bytes
- STCP does not perform adaptive congestion control
- Do not send data outside the sending window
- The first byte of all windows is always the last acknowledged byte of data.

#### TCP Options:
- STCP ignores the option field in the packets it receives
- STCP does not generate options in the packets it sends

#### Retransmissions
- You will not have to implement retransmissions since the network layer is assumed to be _reliable_.

#### Network Initiation
- Three way handshake, just like TCP defined in [RFC 793](http://www.ietf.org/rfc/rfc793.txt)
1. The requesting active end sends a SYN packet to the other end with the appropriate seq number (seqx) in the header. The active end then sits waiting for a SYN_ACK.
2. The passive end sends a SYN_ACK with its own sequence number (seqy) and acks with the number (seqx+1). The passive end waits for an ACK.
3. The active end records seqy so that it will expect the next byte from the passive end to start at (seqy+1). It ACKs the passive end's SYN request, and changes its state to the established state.

#### Network Termination
- four-way handshake, same as TCP defined in [RFC 793](http://www.ietf.org/rfc/rfc793.txt)
1. When one of the peers has finished sending data, it transmits a FIN segment to the other side. At this point, no more data will be sent from that peer. The FIN flag may be set in the last data segment transmitted by the peer. (You are not required to combine FIN + data packets, but your receiver must be capable of handling them).
2. The peer waits for an ACK of its FIN segment, as usual. If both sides have sent FINs and received acknowledgements for them, the connection is closed once the FIN is acknowledged. Otherwise, the peer continues receiving data until the other side also initiates a connection close request. If no ACK for the FIN is ever received, it terminates its end of the connection anyway.

### Testing:
You are given test server and client programs that use MYSOCK and STCP.  The server works as follows:
1. Client sends server the path to a file with some test input
2. The server opens the file, reads the input and sends the input back to the client
3. The client prints what it receives from the server into a file `rcvd`.

Server usage:
```
./server [port to listen to]
```

Client usage:
```
./client -f [file-path] 127.0.0.1:[server port]
```
- **Do not change these client and server programs since this is also how we will test your STCP implementation**
- debugging printfs will not affect the autograder.

### Submission
- Please submit just `transport.c`

### Coding Tips:

- You only need to change `transport.c`
- You will need to use many functions in `stcp_api.h` notably: `stcp_network_send()`, `stcp_network_recv()`, `stcp_app_recv()` and `stcp_app_send()`.
- Look at the functions in `mysock_api.c` to see how the client works with the STCP layer.