package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	homedir "github.com/mitchellh/go-homedir"
)

var (
	credsPath   = flag.String("credentialsFile", "", "path to aws credentials file")
	outputPath  = flag.String("out", "flow-logs.pcap", "path to output pcap file to")
	prefix      = flag.String("prefix", "", "prefix to use to find flow logs/streams")
	profileName = flag.String("profile", "default", "profile to use in your aws credentials file")
	region      = flag.String("region", "us-east-1", "region to use")
	zeroLen     = flag.Bool("zero-len", true, "zero out packet lengths")
)

func main() {
	flag.Parse()
	if *credsPath == "" {
		home, err := homedir.Dir()
		if err != nil {
			panic(err)
		}
		p := path.Join(home, ".aws", "credentials")
		credsPath = &p
	}
	config := aws.NewConfig().WithCredentials(credentials.NewSharedCredentials(*credsPath, *profileName))
	config = config.WithMaxRetries(3)
	config = config.WithRegion(*region)
	sess := session.Must(session.NewSession(config))
	svc := cloudwatchlogs.New(sess, config)
	groupsResp, err := svc.DescribeLogGroups(&cloudwatchlogs.DescribeLogGroupsInput{
		LogGroupNamePrefix: prefix,
	})
	if err != nil {
		panic(err)
	}
	lgName := groupsResp.LogGroups[0].LogGroupName
	orderBy := "LastEventTime"
	truePtr := true
	streamsResp, err := svc.DescribeLogStreams(&cloudwatchlogs.DescribeLogStreamsInput{
		Descending:   &truePtr,
		LogGroupName: lgName,
		OrderBy:      &orderBy,
	})
	if err != nil {
		panic(err)
	}
	stream := streamsResp.LogStreams[0]
	eventsResp, err := svc.GetLogEvents(&cloudwatchlogs.GetLogEventsInput{
		LogGroupName:  lgName,
		LogStreamName: stream.LogStreamName,
		StartFromHead: &truePtr,
	})
	if err != nil {
		panic(err)
	}
	file, err := os.OpenFile(*outputPath, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	w := pcapgo.NewWriter(file)
	if err := w.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		panic(err)
	}
	for _, e := range eventsResp.Events {
		components := strings.Split(*e.Message, " ")
		lengthInt := 6
		if !*zeroLen {
			var err error
			lengthInt, err = strconv.Atoi(components[9])
			if err != nil {
				log.Println("got err", err)
				continue
			}
		}
		tsInt, err := strconv.Atoi(components[10])
		if err != nil {
			log.Println("got err", err)
			continue
		}
		srcPortInt, err := strconv.Atoi(components[5])
		if err != nil {
			log.Println("got err", err)
			continue
		}
		dstPortInt, err := strconv.Atoi(components[6])
		if err != nil {
			log.Println("got err", err)
			continue
		}
		packetsInt, err := strconv.Atoi(components[8])
		if err != nil {
			log.Println("got err", err)
			continue
		}
		protoInt, err := strconv.Atoi(components[7])
		if err != nil {
			log.Println("got err", err)
			continue
		}
		fmt.Println("proto:", layers.IPProtocol(protoInt).String())
		fmt.Println("num packets:", packetsInt)
		for i := 0; i < packetsInt+1; i++ {
			length := 0
			if lengthInt > 65536 {
				lengthInt = lengthInt - 65536 - 54
				length = 65536
			} else {
				length = lengthInt + 54
			}
			p := gopacket.CaptureInfo{
				CaptureLength:  length,
				InterfaceIndex: 0,
				Length:         length,
				Timestamp:      time.Unix(int64(tsInt), 0),
			}
			eth := &layers.Ethernet{
				SrcMAC:       net.HardwareAddr([]byte{0, 0, 0, 0, 0, 0}),
				DstMAC:       net.HardwareAddr([]byte{255, 255, 255, 255, 255, 255}),
				EthernetType: layers.EthernetTypeIPv4,
			}
			ip := &layers.IPv4{
				Checksum:   0x4324,
				DstIP:      net.ParseIP(components[4]),
				Flags:      layers.IPv4DontFragment,
				FragOffset: 0,
				Id:         uint16(i),
				Length:     52,
				Protocol:   layers.IPProtocol(protoInt),
				SrcIP:      net.ParseIP(components[3]),
				TTL:        42,
				Version:    4,
			}
			tcp := &layers.TCP{
				SrcPort: layers.TCPPort(srcPortInt),
				DstPort: layers.TCPPort(dstPortInt),
			}
			payload := gopacket.Payload(make([]byte, length-54))
			buf := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{
				FixLengths: true,
			}
			if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, payload); err != nil {
				log.Println("got err", err)
				continue
			}
			if err := w.WritePacket(p, buf.Bytes()); err != nil {
				log.Println("got err", err)
				continue
			}

		}
	}
}
