package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"strings"
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

// ParseDNSHeader parses a DNS header from the buffer
func ParseDNSHeader(buf []byte) *DNSHeader {
	if len(buf) < 12 {
		return nil
	}

	header := &DNSHeader{}

	// Bytes 0-1: ID
	header.ID = binary.BigEndian.Uint16(buf[0:2])

	// Byte 2: QR(1) | OPCODE(4) | AA(1) | TC(1) | RD(1)
	byte2 := buf[2]
	header.QR = (byte2 & 0x80) != 0     // Bit 7
	header.OPCODE = (byte2 >> 3) & 0x0F // Bits 3-6
	header.AA = (byte2 & 0x04) != 0     // Bit 2
	header.TC = (byte2 & 0x02) != 0     // Bit 1
	header.RD = (byte2 & 0x01) != 0     // Bit 0

	// Byte 3: RA(1) | Z(3) | RCODE(4)
	byte3 := buf[3]
	header.RA = (byte3 & 0x80) != 0 // Bit 7
	header.Z = (byte3 >> 4) & 0x07  // Bits 4-6
	header.RCODE = byte3 & 0x0F     // Bits 0-3

	// Bytes 4-5: QDCOUNT
	header.QDCOUNT = binary.BigEndian.Uint16(buf[4:6])

	// Bytes 6-7: ANCOUNT
	header.ANCOUNT = binary.BigEndian.Uint16(buf[6:8])

	// Bytes 8-9: NSCOUNT
	header.NSCOUNT = binary.BigEndian.Uint16(buf[8:10])

	// Bytes 10-11: ARCOUNT
	header.ARCOUNT = binary.BigEndian.Uint16(buf[10:12])

	return header
}

// DNSQuestion represents a question in the question section
type DNSQuestion struct {
	Name  []byte // Domain name as a sequence of labels
	Type  uint16 // Query type
	Class uint16 // Query class
}

// ToBytes serializes the DNS question to bytes
func (q *DNSQuestion) ToBytes() []byte {
	buf := make([]byte, 0)

	// Add the domain name (already in label format)
	buf = append(buf, q.Name...)

	// Add Type (2 bytes, big-endian)
	typeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(typeBytes, q.Type)
	buf = append(buf, typeBytes...)

	// Add Class (2 bytes, big-endian)
	classBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(classBytes, q.Class)
	buf = append(buf, classBytes...)

	return buf
}

// ParseDomainName parses a domain name from the buffer starting at offset
// Returns the uncompressed domain name bytes and the new offset
// Handles DNS name compression (pointers) according to RFC 1035 section 4.1.4
func ParseDomainName(buf []byte, offset int) ([]byte, int) {
	name := make([]byte, 0)
	pos := offset
	jumped := false
	jumpPos := 0

	for {
		if pos >= len(buf) {
			break
		}

		length := buf[pos]

		// Check if this is a compression pointer (top 2 bits are 11)
		if length&0xC0 == 0xC0 {
			// This is a pointer
			if pos+1 >= len(buf) {
				break
			}

			// The pointer is 14 bits: current byte (lower 6 bits) + next byte
			pointer := int(binary.BigEndian.Uint16(buf[pos:pos+2]) & 0x3FFF)

			// If we haven't jumped yet, save the position to return
			if !jumped {
				jumpPos = pos + 2
				jumped = true
			}

			// Follow the pointer
			pos = pointer
			continue
		}

		if length == 0 {
			// Null byte terminates the domain name
			name = append(name, 0)
			pos++
			break
		}

		// Add the length byte
		name = append(name, length)
		pos++

		// Add the label content
		if pos+int(length) <= len(buf) {
			name = append(name, buf[pos:pos+int(length)]...)
			pos += int(length)
		} else {
			break
		}
	}

	// If we jumped, return the position after the pointer
	// Otherwise return the current position
	if jumped {
		return name, jumpPos
	}
	return name, pos
}

// ParseDNSQuestion parses a DNS question from the buffer starting at offset
func ParseDNSQuestion(buf []byte, offset int) (*DNSQuestion, int) {
	// Parse domain name
	name, pos := ParseDomainName(buf, offset)

	// Parse Type (2 bytes)
	if pos+2 > len(buf) {
		return nil, pos
	}
	qType := binary.BigEndian.Uint16(buf[pos : pos+2])
	pos += 2

	// Parse Class (2 bytes)
	if pos+2 > len(buf) {
		return nil, pos
	}
	qClass := binary.BigEndian.Uint16(buf[pos : pos+2])
	pos += 2

	return &DNSQuestion{
		Name:  name,
		Type:  qType,
		Class: qClass,
	}, pos
}

// ParseDNSRecord parses a DNS resource record from the buffer starting at offset
func ParseDNSRecord(buf []byte, offset int) (*DNSRecord, int) {
	// Parse domain name
	name, pos := ParseDomainName(buf, offset)

	// Need at least 10 more bytes for Type, Class, TTL, Length
	if pos+10 > len(buf) {
		return nil, pos
	}

	// Parse Type (2 bytes)
	rType := binary.BigEndian.Uint16(buf[pos : pos+2])
	pos += 2

	// Parse Class (2 bytes)
	rClass := binary.BigEndian.Uint16(buf[pos : pos+2])
	pos += 2

	// Parse TTL (4 bytes)
	ttl := binary.BigEndian.Uint32(buf[pos : pos+4])
	pos += 4

	// Parse Length (2 bytes)
	length := binary.BigEndian.Uint16(buf[pos : pos+2])
	pos += 2

	// Parse Data
	if pos+int(length) > len(buf) {
		return nil, pos
	}
	data := make([]byte, length)
	copy(data, buf[pos:pos+int(length)])
	pos += int(length)

	return &DNSRecord{
		Name:   name,
		Type:   rType,
		Class:  rClass,
		TTL:    ttl,
		Length: length,
		Data:   data,
	}, pos
}

// DNSRecord represents a resource record in the answer/authority/additional sections
type DNSRecord struct {
	Name   []byte // Domain name as a sequence of labels
	Type   uint16 // Record type
	Class  uint16 // Record class
	TTL    uint32 // Time to live in seconds
	Length uint16 // Length of RDATA
	Data   []byte // Record data (RDATA)
}

// ToBytes serializes the DNS record to bytes
func (r *DNSRecord) ToBytes() []byte {
	buf := make([]byte, 0)

	// Add the domain name (already in label format)
	buf = append(buf, r.Name...)

	// Add Type (2 bytes, big-endian)
	typeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(typeBytes, r.Type)
	buf = append(buf, typeBytes...)

	// Add Class (2 bytes, big-endian)
	classBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(classBytes, r.Class)
	buf = append(buf, classBytes...)

	// Add TTL (4 bytes, big-endian)
	ttlBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(ttlBytes, r.TTL)
	buf = append(buf, ttlBytes...)

	// Add Length (2 bytes, big-endian)
	lengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthBytes, r.Length)
	buf = append(buf, lengthBytes...)

	// Add Data (RDATA)
	buf = append(buf, r.Data...)

	return buf
}

// ForwardQuery forwards a DNS query with a single question to the resolver
// Returns the answer records from the resolver's response
func ForwardQuery(question *DNSQuestion, resolverAddr string) ([]*DNSRecord, error) {
	// Create a DNS query packet with a single question
	queryHeader := DNSHeader{
		ID:      1234, // Use a fixed ID for forwarded queries
		QR:      false,
		OPCODE:  0,
		AA:      false,
		TC:      false,
		RD:      true, // Request recursion
		RA:      false,
		Z:       0,
		RCODE:   0,
		QDCOUNT: 1,
		ANCOUNT: 0,
		NSCOUNT: 0,
		ARCOUNT: 0,
	}

	// Build the query packet
	queryPacket := queryHeader.ToBytes()
	queryPacket = append(queryPacket, question.ToBytes()...)

	// Resolve the resolver address
	udpAddr, err := net.ResolveUDPAddr("udp", resolverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve resolver address: %v", err)
	}

	// Create a UDP connection
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to resolver: %v", err)
	}
	defer conn.Close()

	// Send the query
	_, err = conn.Write(queryPacket)
	if err != nil {
		return nil, fmt.Errorf("failed to send query to resolver: %v", err)
	}

	// Receive the response
	responseBuf := make([]byte, 512)
	n, err := conn.Read(responseBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to read response from resolver: %v", err)
	}

	responseData := responseBuf[:n]

	// Parse the response header
	responseHeader := ParseDNSHeader(responseData)
	if responseHeader == nil {
		return nil, fmt.Errorf("failed to parse response header")
	}

	// Skip past the header and questions in the response
	offset := 12
	for i := 0; i < int(responseHeader.QDCOUNT); i++ {
		_, newOffset := ParseDNSQuestion(responseData, offset)
		offset = newOffset
	}

	// Parse the answer records
	answers := make([]*DNSRecord, 0)
	for i := 0; i < int(responseHeader.ANCOUNT); i++ {
		record, newOffset := ParseDNSRecord(responseData, offset)
		if record != nil {
			answers = append(answers, record)
			offset = newOffset
		}
	}

	return answers, nil
}

func main() {
	// Parse command-line arguments
	resolverAddr := flag.String("resolver", "", "DNS resolver address (e.g., 8.8.8.8:53)")
	flag.Parse()

	fmt.Println("Logs from your program will appear here!")
	if *resolverAddr != "" {
		fmt.Printf("Using resolver: %s\n", *resolverAddr)
	}

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

		// Parse the incoming DNS query
		queryData := buf[:size]

		// Parse the header from the query
		queryHeader := ParseDNSHeader(queryData)
		if queryHeader == nil {
			fmt.Println("Failed to parse DNS header")
			continue
		}

		fmt.Printf("Query ID: %d, OPCODE: %d, RD: %v\n", queryHeader.ID, queryHeader.OPCODE, queryHeader.RD)

		// Parse questions from the query
		questions := make([]*DNSQuestion, 0)
		offset := 12 // Start after the header

		for i := 0; i < int(queryHeader.QDCOUNT); i++ {
			question, newOffset := ParseDNSQuestion(queryData, offset)
			if question != nil {
				questions = append(questions, question)
				offset = newOffset
			}
		}

		fmt.Printf("Parsed %d questions from query\n", len(questions))

		// Create answer records for each question
		answers := make([]*DNSRecord, 0)

		if *resolverAddr != "" && strings.TrimSpace(*resolverAddr) != "" {
			// Forward mode: forward each question to the resolver
			fmt.Println("Forwarding queries to resolver...")
			for _, question := range questions {
				forwardedAnswers, err := ForwardQuery(question, *resolverAddr)
				if err != nil {
					fmt.Printf("Error forwarding query: %v\n", err)
					// Create a default answer on error
					answer := &DNSRecord{
						Name:   question.Name,
						Type:   question.Type,
						Class:  question.Class,
						TTL:    60,
						Length: 4,
						Data:   []byte{8, 8, 8, 8},
					}
					answers = append(answers, answer)
				} else {
					answers = append(answers, forwardedAnswers...)
				}
			}
		} else {
			// Direct mode: create default answers
			for _, question := range questions {
				// Create an A record answer
				// Using 8.8.8.8 as the IP address
				answer := &DNSRecord{
					Name:   question.Name,
					Type:   question.Type,
					Class:  question.Class,
					TTL:    60,                 // 60 seconds
					Length: 4,                  // IPv4 address is 4 bytes
					Data:   []byte{8, 8, 8, 8}, // 8.8.8.8
				}
				answers = append(answers, answer)
			}
		}

		// Determine RCODE based on OPCODE
		// 0 (no error) if OPCODE is 0 (standard query)
		// 4 (not implemented) for other OPCODE values
		rcode := uint8(0)
		if queryHeader.OPCODE != 0 {
			rcode = 4 // Not implemented
		}

		// Create DNS response header
		header := DNSHeader{
			ID:      queryHeader.ID,     // Mirror the ID from the query
			QR:      true,               // This is a response
			OPCODE:  queryHeader.OPCODE, // Mirror OPCODE from query
			AA:      false,
			TC:      false,
			RD:      queryHeader.RD, // Mirror RD from query
			RA:      false,
			Z:       0,
			RCODE:   rcode,                  // 0 for standard query, 4 otherwise
			QDCOUNT: uint16(len(questions)), // Number of questions
			ANCOUNT: uint16(len(answers)),   // Number of answers
			NSCOUNT: 0,
			ARCOUNT: 0,
		}

		// Build the response
		response := header.ToBytes()

		// Add all questions to the response
		for _, question := range questions {
			response = append(response, question.ToBytes()...)
		}

		// Add all answers to the response
		for _, answer := range answers {
			response = append(response, answer.ToBytes()...)
		}

		_, err = udpConn.WriteToUDP(response, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
