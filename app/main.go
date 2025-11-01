package main

import (
	"encoding/binary"
	"fmt"
	"net"
)

// DNSHeader represents the header section of a DNS message
type DNSHeader struct {
	ID      uint16 // Packet Identifier
	QR      bool   // Query/Response Indicator (0=query, 1=response)
	OPCODE  uint8  // Operation Code
	AA      bool   // Authoritative Answer
	TC      bool   // Truncation
	RD      bool   // Recursion Desired
	RA      bool   // Recursion Available
	Z       uint8  // Reserved (3 bits)
	RCODE   uint8  // Response Code
	QDCOUNT uint16 // Question Count
	ANCOUNT uint16 // Answer Record Count
	NSCOUNT uint16 // Authority Record Count
	ARCOUNT uint16 // Additional Record Count
}

// ToBytes serializes the DNS header to a 12-byte slice
func (h *DNSHeader) ToBytes() []byte {
	buf := make([]byte, 12)

	// Bytes 0-1: ID
	binary.BigEndian.PutUint16(buf[0:2], h.ID)

	// Byte 2: QR(1) | OPCODE(4) | AA(1) | TC(1) | RD(1)
	var byte2 uint8
	if h.QR {
		byte2 |= 0x80 // QR is bit 7
	}
	byte2 |= (h.OPCODE & 0x0F) << 3 // OPCODE is bits 3-6
	if h.AA {
		byte2 |= 0x04 // AA is bit 2
	}
	if h.TC {
		byte2 |= 0x02 // TC is bit 1
	}
	if h.RD {
		byte2 |= 0x01 // RD is bit 0
	}
	buf[2] = byte2

	// Byte 3: RA(1) | Z(3) | RCODE(4)
	var byte3 uint8
	if h.RA {
		byte3 |= 0x80 // RA is bit 7
	}
	byte3 |= (h.Z & 0x07) << 4 // Z is bits 4-6
	byte3 |= h.RCODE & 0x0F    // RCODE is bits 0-3
	buf[3] = byte3

	// Bytes 4-5: QDCOUNT
	binary.BigEndian.PutUint16(buf[4:6], h.QDCOUNT)

	// Bytes 6-7: ANCOUNT
	binary.BigEndian.PutUint16(buf[6:8], h.ANCOUNT)

	// Bytes 8-9: NSCOUNT
	binary.BigEndian.PutUint16(buf[8:10], h.NSCOUNT)

	// Bytes 10-11: ARCOUNT
	binary.BigEndian.PutUint16(buf[10:12], h.ARCOUNT)

	return buf
}

func main() {
	fmt.Println("Logs from your program will appear here!")

	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}
	defer udpConn.Close()

	buf := make([]byte, 512)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		fmt.Printf("Received %d bytes from %s\n", size, source)

		// Create DNS response header with expected values
		header := DNSHeader{
			ID:      1234, // Expected value
			QR:      true, // This is a response
			OPCODE:  0,    // Standard query
			AA:      false,
			TC:      false,
			RD:      false,
			RA:      false,
			Z:       0,
			RCODE:   0, // No error
			QDCOUNT: 0,
			ANCOUNT: 0,
			NSCOUNT: 0,
			ARCOUNT: 0,
		}

		response := header.ToBytes()

		_, err = udpConn.WriteToUDP(response, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
