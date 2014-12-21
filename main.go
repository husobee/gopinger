package main

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/husobee/gopinger/icmp"
)

func main() {
	dst := "127.0.0.1"
	raddr, err := net.ResolveIPAddr("ip", dst) // *IPAddr
	if err != nil {
		log.Fatalf(`net.ResolveIPAddr("ip", %v") = %v, %v`, dst, raddr, err)
	}

	ipconn, err := net.DialIP("ip4:icmp", nil, raddr) // *IPConn (Conn # # # # #  # # )
	if err != nil {
		log.Fatalf(`net.DialIP("ip4:icmp", %v) = %v`, ipconn, err)
	}

	sendid := uint16(os.Getpid() & 0xffff)
	sendseq := uint16(1)
	//pingpktlen := 64
	data := "hi there!"

	//sendpkt := makePingRequest(sendid, sendseq, pingpktlen, []byte(data))
	packet := icmp.NewEchoRequestMessage(sendid, sendseq, []byte(data))
	fmt.Printf("checksum: %x\n", packet.Header.Header.Checksum)
	_, err = ipconn.Write(packet.Bytes())
	if err != nil {
		panic(err.Error())
	}

}
