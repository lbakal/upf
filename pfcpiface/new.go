// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Intel Corporation

package pfcpiface

import (
	"context"
	"flag"
	"net"

	"google.golang.org/grpc/connectivity"

	pb "github.com/omec-project/upf-epc/pfcpiface/new_pb"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"github.com/wmnsk/go-pfcp/ie"
	"google.golang.org/grpc"
)

var newIP = flag.String("new", "localhost:10514", "NEW IP/port combo")

type new struct {
	client          pb.NEWControlClient
	conn            *grpc.ClientConn
	endMarkerSocket net.Conn
	notifyNewSocket net.Conn
	endMarkerChan   chan []byte
	qciQosMap       map[uint8]*QosConfigVal
}

func (b *new) IsConnected(accessIP *net.IP) bool {
	if (b.conn == nil) || (b.conn.GetState() != connectivity.Ready) {
		return false
	}

	return true
}

func (b *new) SendEndMarkers(endMarkerList *[][]byte) error {
	for _, eMarker := range *endMarkerList {
		b.endMarkerChan <- eMarker
	}

	return nil
}

func (b *new) AddSliceInfo(sliceInfo *SliceInfo) error {
	log.Println("AddSliceInfo - addSliceMeter")
	return nil
}

func (b *new) SendMsgToUPF(
	method upfMsgType, rules PacketForwardingRules, updated PacketForwardingRules) uint8 {
	// create context
	var cause uint8 = ie.CauseRequestAccepted

	pdrs := rules.pdrs
	fars := rules.fars
	qers := rules.qers

	if method == upfMsgTypeMod {
		pdrs = updated.pdrs
		fars = updated.fars
		qers = updated.qers
	}

	calls := len(pdrs) + len(fars) + len(qers)
	if calls == 0 {
		return cause
	}

	for _, pdr := range pdrs {
		log.Traceln(method, pdr)

		switch method {
		case upfMsgTypeAdd:
			log.Println("SendMsgToUPF - PDR - upfMsgTypeAdd")
			fallthrough
		case upfMsgTypeMod:
			log.Println("SendMsgToUPF - PDR - upfMsgTypeMod")
		case upfMsgTypeDel:
			log.Println("SendMsgToUPF - PDR - upfMsgTypeDel")
		}
	}

	for _, far := range fars {
		log.Traceln(method, far)

		switch method {
		case upfMsgTypeAdd:
			log.Println("SendMsgToUPF - FAR - upfMsgTypeAdd")
			fallthrough
		case upfMsgTypeMod:
			log.Println("SendMsgToUPF - FAR - upfMsgTypeMod")
		case upfMsgTypeDel:
			log.Println("SendMsgToUPF - FAR- upfMsgTypeDel")
		}
	}

	for _, qer := range qers {
		log.Traceln(method, qer)

		switch method {
		case upfMsgTypeAdd:
			log.Println("SendMsgToUPF - QER - upfMsgTypeAdd")
			fallthrough
		case upfMsgTypeMod:
			log.Println("SendMsgToUPF - QER - upfMsgTypeMod")
		case upfMsgTypeDel:
			log.Println("SendMsgToUPF - QER- upfMsgTypeDel")
		}
	}

	return cause
}

func (b *new) Exit() {
	log.Println("Exit function New")
	b.conn.Close()
}

func (b *new) SummaryLatencyJitter(uc *upfCollector, ch chan<- prometheus.Metric) {
	log.Println("SummaryLatencyJitter - measureUpf")
}

func (b *new) SessionStats(pc *PfcpNodeCollector, ch chan<- prometheus.Metric) (err error) {
	log.Println("SessionStats")
	return
}

// setUpfInfo is only called at pfcp-agent's startup
// it clears all the state in NEW
func (b *new) SetUpfInfo(u *upf, conf *Conf) {
	log.Println("SetUpfInfo new")
}

func (b *new) addApplicationQER(ctx context.Context, gate uint64, srcIface uint8,
	cir uint64, pir uint64, cbs uint64, pbs uint64,
	ebs uint64, qer qer) {
	log.Println("addApplicationQER")
}

func (b *new) delApplicationQER(
	ctx context.Context, srcIface uint8, qer qer) {
	log.Println("delApplicationQER")
}

func (b *new) setActionValue(f far) uint8 {
	log.Println("setActionValue")
	// default action
	return farDrop
}

func (b *new) addSessionQER(ctx context.Context, gate uint64, srcIface uint8,
	cir uint64, pir uint64, cbs uint64,
	pbs uint64, ebs uint64, qer qer) {
	log.Println("addSessionQER")
}

func (b *new) delSessionQER(ctx context.Context, srcIface uint8, qer qer) {
	log.Println("delSessionQER")
}
