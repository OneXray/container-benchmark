package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestStartBarrierKeepsBoundedWaitAndSafeErrorClasses(t *testing.T) {
	if startBarrierWait != 15*time.Second {
		t.Fatal("inner barrier no longer matches the outer 15-second budget")
	}
	root := t.TempDir()
	marker := filepath.Join(root, "private-marker")
	if err := os.WriteFile(marker, []byte("start\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := startBarrier(filepath.Join(root, "ready"), marker, 1); err != nil {
		t.Fatal("valid local barrier failed")
	}
	if err := os.WriteFile(marker, []byte("wrong\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		err  error
		want error
	}{
		{startBarrier("", marker, 1), errBarrierInvalid},
		{startBarrier(root, marker, 1), errBarrierReadyIO},
		{awaitStartBarrier(root, time.Now().Add(time.Second)), errBarrierReadIO},
		{awaitStartBarrier(marker, time.Now().Add(time.Second)), errBarrierInvalid},
		{awaitStartBarrier(marker, time.Unix(1, 0)), errBarrierTimeout},
	}
	for _, test := range cases {
		if !errors.Is(test.err, test.want) || strings.Contains(test.err.Error(), root) {
			t.Fatal("barrier did not return a fixed safe error classification")
		}
	}
	for _, test := range []struct {
		err  error
		want string
	}{
		{errBarrierTimeout, "dns-start-barrier-timeout"},
		{errBarrierReadyIO, "dns-start-barrier-ready-io"},
		{fmt.Errorf("PRIVATE_MARKER: %w", errBarrierReadIO), "dns-start-barrier-read-io"},
		{errors.New("PRIVATE_MARKER"), "dns-start-barrier-invalid"},
	} {
		if dnsBarrierError(test.err).Error() != test.want {
			t.Fatal("DNS barrier leaked or lost its safe error classification")
		}
	}
}

type controlDeadlineRecorder struct {
	net.Conn
	deadline time.Time
}

func (c *controlDeadlineRecorder) SetDeadline(deadline time.Time) error {
	c.deadline = deadline
	return nil
}

func TestFlowControlDeadlineResetsWithoutExtendingLoadBudget(t *testing.T) {
	connection := &controlDeadlineRecorder{deadline: time.Unix(1, 0)}
	before := time.Now()
	if setFlowControlDeadline(connection, 15) != nil ||
		connection.deadline.Before(before.Add(30*time.Second)) ||
		connection.deadline.After(time.Now().Add(30*time.Second)) {
		t.Fatal("control deadline did not reset to the existing seconds+15 budget")
	}
}

func TestFailedFlowStillCompletesItsReadinessWait(t *testing.T) {
	var ready sync.WaitGroup
	ready.Add(1)
	// The invalid endpoint is rejected locally, without a socket/server.
	rows := clientFlow("missing-port", request{Transport: "udp"}, &ready, make(chan struct{}))
	if len(rows) != 1 || rows[0].Error != "control connect" {
		t.Fatal("invalid endpoint did not produce the fixed setup failure")
	}
	done := make(chan struct{})
	go func() { ready.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("failed preparation deadlocked the sequential readiness wait")
	}
}

type fixtureDatagram struct {
	payload []byte
	peer    netip.AddrPort
}
type fixturePacketSocket struct {
	packets chan fixtureDatagram
	done    chan struct{}
	closed  sync.Once
	writes  []fixtureDatagram
}

func newFixturePacketSocket() *fixturePacketSocket {
	return &fixturePacketSocket{packets: make(chan fixtureDatagram, 2), done: make(chan struct{})}
}
func (s *fixturePacketSocket) ReadFromUDPAddrPort(buf []byte) (int, netip.AddrPort, error) {
	select {
	case packet := <-s.packets:
		return copy(buf, packet.payload), packet.peer, nil
	case <-s.done:
		return 0, netip.AddrPort{}, net.ErrClosed
	}
}
func (s *fixturePacketSocket) WriteToUDPAddrPort(buf []byte, peer netip.AddrPort) (int, error) {
	s.writes = append(s.writes, fixtureDatagram{payload: append([]byte(nil), buf...), peer: peer})
	return len(buf), nil
}
func (s *fixturePacketSocket) Close() error { s.closed.Do(func() { close(s.done) }); return nil }
func (s *fixturePacketSocket) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(192, 0, 2, 5), Port: 43000}
}
func (s *fixturePacketSocket) SetDeadline(time.Time) error      { return nil }
func (s *fixturePacketSocket) SetReadDeadline(time.Time) error  { return nil }
func (s *fixturePacketSocket) SetWriteDeadline(time.Time) error { return nil }

func TestCyclingUDPUsesOneSourceSocketAndRejectsUnexpectedResponseEndpoints(t *testing.T) {
	socket := newFixturePacketSocket()
	defer socket.Close()
	peers := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:40000"), netip.MustParseAddrPort("192.0.2.1:40001")}
	c := &cyclingPacketConn{datagramSocket: socket, peers: peers, allowed: map[netip.AddrPort]struct{}{peers[0]: {}, peers[1]: {}}}
	for index := 0; index < 6; index++ {
		if _, err := c.Write([]byte{byte(index)}); err != nil {
			t.Fatal(err)
		}
		if socket.writes[index].peer != peers[index%2] || c.LocalAddr().String() != "192.0.2.5:43000" {
			t.Fatal("destination rotation changed source socket or rate sequence")
		}
	}
	var buf [8]byte
	for _, peer := range peers {
		socket.packets <- fixtureDatagram{payload: []byte("valid"), peer: peer}
		if n, err := c.Read(buf[:]); err != nil || string(buf[:n]) != "valid" {
			t.Fatal("allowed destination response rejected")
		}
	}
	for _, packet := range []fixtureDatagram{
		{payload: []byte("wrong"), peer: netip.MustParseAddrPort("192.0.2.1:40002")},
		{payload: []byte("wrong"), peer: netip.MustParseAddrPort("192.0.2.2:40000")},
		{payload: []byte("oversized"), peer: peers[0]},
	} {
		socket.packets <- packet
		if _, err := c.Read(buf[:]); !errors.Is(err, errPacketSourceSize) {
			t.Fatal("unexpected source/size accepted")
		}
	}
}

func TestOriginPortFanInKeepsPayloadsAndJoinsBlockedReaders(t *testing.T) {
	first, second := newFixturePacketSocket(), newFixturePacketSocket()
	peers := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.5:43000"), netip.MustParseAddrPort("192.0.2.5:43001")}
	c := newOriginPortsConn([]datagramSocket{first, second}, peers)
	defer c.Close()
	first.packets <- fixtureDatagram{payload: []byte("first"), peer: peers[0]}
	second.packets <- fixtureDatagram{payload: []byte("second"), peer: peers[1]}
	seen := make(map[string]bool)
	var buf [8]byte
	for index := 0; index < 2; index++ {
		if n, err := c.Read(buf[:]); err != nil {
			t.Fatal(err)
		} else {
			seen[string(buf[:n])] = true
		}
		if _, err := c.Write([]byte{byte(index)}); err != nil {
			t.Fatal(err)
		}
	}
	if !seen["first"] || !seen["second"] || len(first.writes) != 1 || len(second.writes) != 1 ||
		first.writes[0].peer != peers[0] || second.writes[0].peer != peers[1] {
		t.Fatal("origin fan-in lost payload or destination")
	}
	closed := make(chan struct{})
	go func() { c.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("origin close did not join blocked readers")
	}
}

func TestMultipleUDPDestinationsAreAnOptionalFixtureBoundNotExtraFlows(t *testing.T) {
	r := request{Transport: "udp", Direction: "up", Seconds: 60, BytesPerSecond: 3906250, UDPDestinations: 64}
	if err := validate(r); err != nil {
		t.Fatal(err)
	}
	before := count(r)
	r.UDPDestinations = 1
	if count(r) != before || validate(r) != nil {
		t.Fatal("destination diversity multiplied rate or sequence count")
	}
	for _, invalid := range []int{-1, 257} {
		r.UDPDestinations = invalid
		if validate(r) == nil {
			t.Fatal("out-of-bound fixture destination request accepted")
		}
	}
	r.UDPDestinations, r.Transport = 64, "tcp"
	if validate(r) == nil {
		t.Fatal("TCP request acquired UDP sockets")
	}
}

func TestKernelTUNDNSUsesControlledQuestionAndVerifiesOrigin(t *testing.T) {
	for _, expected := range []string{"192.0.2.1", "2001:db8::1"} {
		query, ip, err := kernelDNSQuestion("benchmark.test", expected)
		if err != nil {
			t.Fatal(err)
		}
		qtype := byte(1)
		if len(ip) == 16 {
			qtype = 28
		}
		if query[len(query)-3] != qtype || len(ip) != len(net.ParseIP(expected).To4()) && len(ip) != 16 {
			t.Fatal("DNS question lost address family")
		}
		reply := append([]byte(nil), query...)
		copy(reply[2:8], []byte{0x81, 0x80, 0, 1, 0, 1})
		reply = append(reply, 0xc0, 0x0c, 0, qtype, 0, 1, 0, 0, 0, 30, 0, byte(len(ip)))
		reply = append(reply, ip...)
		if !validKernelDNSReply(query, reply, ip) {
			t.Fatal("controlled origin answer rejected")
		}
		reply[len(reply)-1] ^= 1
		if validKernelDNSReply(query, reply, ip) {
			t.Fatal("wrong origin answer accepted")
		}
		if validKernelDNSReply(query, query[:8], ip) {
			t.Fatal("short DNS reply accepted")
		}
	}
	if _, _, err := kernelDNSQuestion("benchmark.test", "private-not-an-IP"); err == nil {
		t.Fatal("host DNS fallback was accepted")
	}
}

func TestKernelTUNDNSAllowsResolverAuthorityFlagsWithoutWeakeningOriginChecks(t *testing.T) {
	for _, origin := range []string{"192.0.2.1", "2001:db8::1"} {
		t.Run(origin, func(t *testing.T) {
			query, ip, err := kernelDNSQuestion("controlled.test", origin)
			if err != nil {
				t.Fatal(err)
			}
			// Response identity is compared to this query, never to a constant.
			binary.BigEndian.PutUint16(query[:2], 0xbead)
			answer := func(flags uint16) []byte {
				reply := append([]byte(nil), query...)
				binary.BigEndian.PutUint16(reply[2:4], flags)
				binary.BigEndian.PutUint16(reply[6:8], 1)
				reply = append(reply, 0xc0, 0x0c, 0, query[len(query)-3], 0, 1, 0, 0, 0, 30, 0, byte(len(ip)))
				return append(reply, ip...)
			}
			for _, flags := range []uint16{0x8100, 0x8180, 0x8500, 0x8580} {
				if !validKernelDNSReply(query, answer(flags), ip) {
					t.Fatalf("valid authority/recursion flags %#04x rejected", flags)
				}
			}
			for _, flags := range []uint16{0x0180, 0x8980, 0x8380, 0x8183, 0x81c0, 0x8080} {
				if validKernelDNSReply(query, answer(flags), ip) {
					t.Fatalf("invalid QR/opcode/TC/RCODE/Z/RD flags %#04x accepted", flags)
				}
			}
			for _, mutate := range []func([]byte){
				func(reply []byte) { reply[0] ^= 1 },
				func(reply []byte) { reply[12] ^= 1 },
				func(reply []byte) { reply[5] = 0 },
				func(reply []byte) { reply[7] = 2 },
				func(reply []byte) { reply[len(reply)-1] ^= 1 },
			} {
				reply := answer(0x8580)
				mutate(reply)
				if validKernelDNSReply(query, reply, ip) {
					t.Fatal("wrong transaction/question/count/origin accepted")
				}
			}
			if validKernelDNSReply(query[:8], answer(0x8580), ip) {
				t.Fatal("short question accepted")
			}
		})
	}
}

// In-memory packet validation exercises the actual shared sender, not a host
// UDP server or a replacement scheduler. Only the sender mutates each recorder.
type recordingUDPConn struct {
	net.Conn
	seed    uint64
	packets int64
}

func (c *recordingUDPConn) Write(payload []byte) (int, error) {
	if len(payload) != 32 || binary.LittleEndian.Uint64(payload) != uint64(c.packets) || !check(payload, c.seed) {
		return 0, errors.New("fixture packet sequence or pattern mismatch")
	}
	c.packets++
	return len(payload), nil
}

func runUDPFixtureJobs(t *testing.T, amount int, rate int64, rejected int) {
	t.Helper()
	input := make(chan *udpSendJob, amount)
	jobs := make([]*udpSendJob, amount)
	for index := range jobs {
		r := request{Transport: "udp", Direction: "down", Seconds: 5,
			BytesPerSecond: rate, Seed: uint64(index), Probe: true, ProbeRounds: 100}
		if err := validate(r); err != nil {
			t.Fatal(err)
		}
		jobs[index] = &udpSendJob{
			conn: &recordingUDPConn{seed: r.Seed}, r: r,
			done: make(chan result, 1), out: result{Windows: make([]int64, r.Seconds+3)},
		}
		input <- jobs[index]
	}
	close(input)
	finished := make(chan struct{})
	peak := 0
	go func() { peak = runUDPSender(input); close(finished) }()
	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		t.Fatal("closed UDP input failed to drain its owned jobs")
	}
	denied := 0
	for _, job := range jobs {
		select {
		case out := <-job.done:
			if out.ErrorKind == "workload-bound" {
				denied++
				if out.Packets != 0 || out.Bytes != 0 || job.conn.(*recordingUDPConn).packets != 0 {
					t.Fatal("rejected workload sent partial payload")
				}
			} else if out.Error != "" || out.Packets != 100 || out.Bytes != 3200 || job.conn.(*recordingUDPConn).packets != 100 {
				t.Fatalf("admitted job completed early or lost payload: %+v", out)
			}
		default:
			t.Fatal("sender returned without completing or rejecting every job")
		}
	}
	if denied != rejected {
		t.Fatalf("expected %d workload rejections, got %d", rejected, denied)
	}
	if peak != amount-rejected {
		t.Fatalf("expected %d simultaneously active jobs, got %d", amount-rejected, peak)
	}
}

func TestUDPSharedSenderAdmitsMoreThan64JobsAndDrainsEveryPacket(t *testing.T) {
	runUDPFixtureJobs(t, 128, 500000, 0)
}

func TestUDPSharedSenderRetainsAggregateRateAndExternalJobBounds(t *testing.T) {
	t.Run("aggregate-two-Gbps", func(t *testing.T) {
		// Two 1 Gbps senders fit exactly; a third must be rejected, not
		// silently serialized or reported as completed application payload.
		runUDPFixtureJobs(t, 3, maxAggregateBytesPerSecond/2, 1)
	})
	t.Run("external-job-count", func(t *testing.T) {
		// All jobs together remain below 1 Gbps: only the tool's job count
		// rejects this extra request. No production connection cap changes.
		runUDPFixtureJobs(t, maxUDPJobs+1, 100000, 1)
	})
}

type orderedUDPConn struct {
	recordingUDPConn
	flow  int
	order *[]int
}

func (c *orderedUDPConn) Write(payload []byte) (int, error) {
	n, err := c.recordingUDPConn.Write(payload)
	if err == nil {
		*c.order = append(*c.order, c.flow)
	}
	return n, err
}

func TestUDPSharedSenderKeepsRoundRobinAndReleasesCompletedFlowRate(t *testing.T) {
	input := make(chan *udpSendJob, 3)
	jobs := make([]*udpSendJob, 3)
	var order []int
	for index := range jobs {
		r := request{Transport: "udp", Direction: "up", Seconds: 1, BytesPerSecond: 300000,
			Seed: uint64(index), Probe: true, ProbeRounds: index + 2}
		jobs[index] = &udpSendJob{conn: &orderedUDPConn{
			recordingUDPConn: recordingUDPConn{seed: r.Seed}, flow: index, order: &order}, r: r,
			done: make(chan result, 1), out: result{Windows: make([]int64, r.Seconds+3)}}
		input <- jobs[index]
	}
	close(input)
	if peak := runUDPSender(input); peak != 3 {
		t.Fatalf("wanted all three jobs admitted, got %d", peak)
	}
	wanted := []int{0, 1, 2, 0, 1, 2, 1, 2, 2}
	if fmt.Sprint(order) != fmt.Sprint(wanted) {
		t.Fatalf("completion changed round-robin order: got %v, want %v", order, wanted)
	}
	for _, job := range jobs {
		out := <-job.done
		if out.Error != "" || out.Packets != count(job.r) || out.Bytes != totalBytes(job.r) {
			t.Fatalf("completed flow rate change lost prescribed payload: %+v", out)
		}
		var windows int64
		for _, window := range out.Windows {
			windows += window
		}
		if windows != out.Bytes {
			t.Fatal("window accounting lost successful bytes")
		}
	}
}

func TestUDPSharedSenderRejectsUnequalRateWithoutSendingPayload(t *testing.T) {
	input := make(chan *udpSendJob, 2)
	jobs := make([]*udpSendJob, 2)
	for index := range jobs {
		r := request{Transport: "udp", Direction: "up", Seconds: 1, BytesPerSecond: int64(index+1) * 300000,
			Seed: uint64(index), Probe: true, ProbeRounds: 2}
		jobs[index] = &udpSendJob{conn: &recordingUDPConn{seed: r.Seed}, r: r,
			done: make(chan result, 1), out: result{Windows: make([]int64, r.Seconds+3)}}
		input <- jobs[index]
	}
	close(input)
	if peak := runUDPSender(input); peak != 1 {
		t.Fatalf("unequal-rate job changed admitted workload: %d", peak)
	}
	first, rejected := <-jobs[0].done, <-jobs[1].done
	if first.Error != "" || first.Packets != 2 || first.Bytes != 64 {
		t.Fatalf("admitted job lost payload: %+v", first)
	}
	if rejected.ErrorKind != "workload-bound" || rejected.Packets != 0 || rejected.Bytes != 0 || jobs[1].conn.(*recordingUDPConn).packets != 0 {
		t.Fatalf("unequal-rate job was not rejected without payload: %+v", rejected)
	}
}

type admittingUDPConn struct {
	recordingUDPConn
	admit func()
}

func (c *admittingUDPConn) Write(payload []byte) (int, error) {
	n, err := c.recordingUDPConn.Write(payload)
	if err == nil && c.admit != nil {
		c.admit()
		c.admit = nil
	}
	return n, err
}

func TestUDPSharedSenderNewJobUsesRateFreedByCompletedJob(t *testing.T) {
	input := make(chan *udpSendJob, 3)
	jobs := make([]*udpSendJob, 3)
	for index := range jobs {
		r := request{Transport: "udp", Direction: "up", Seconds: 1,
			BytesPerSecond: maxAggregateBytesPerSecond / 2, Seed: uint64(index), Probe: true, ProbeRounds: 2}
		if index == 0 {
			r.ProbeRounds = 1
		}
		jobs[index] = &udpSendJob{conn: &recordingUDPConn{seed: r.Seed}, r: r,
			done: make(chan result, 1), out: result{Windows: make([]int64, r.Seconds+3)}}
	}
	jobs[1].conn = &admittingUDPConn{recordingUDPConn: recordingUDPConn{seed: jobs[1].r.Seed},
		admit: func() { input <- jobs[2]; close(input) }}
	input <- jobs[0]
	input <- jobs[1]
	if peak := runUDPSender(input); peak != 2 {
		t.Fatalf("completion changed aggregate-rate admission peak: %d", peak)
	}
	for _, job := range jobs {
		out := <-job.done
		if out.Error != "" || out.Packets != count(job.r) || out.Bytes != totalBytes(job.r) {
			t.Fatalf("completed flow did not release its aggregate rate: %+v", out)
		}
	}
}

func TestTwoGbpsWorkloadBoundsAndPacingRemainExact(t *testing.T) {
	const rate int64 = 250000000
	const seconds = 1800
	for _, transport := range []string{"tcp", "udp"} {
		r := request{Transport: transport, Direction: "up", Seconds: seconds, BytesPerSecond: rate}
		if err := validate(r); err != nil {
			t.Fatalf("%s rejected maximum workload: %v", transport, err)
		}
		wanted := rate * seconds / int64(frameSize(r))
		if count(r) != wanted || totalBytes(r) != wanted*int64(frameSize(r)) {
			t.Fatalf("%s overflowed record or byte count", transport)
		}
		r.BytesPerSecond++
		if validate(r) == nil {
			t.Fatalf("%s admitted a rate above 2 Gbps", transport)
		}
	}
	for _, test := range []struct{ offset, wanted int64 }{
		{0, 0},
		{rate + 1, int64(time.Second) + 4},
		{rate*seconds - 1, int64(seconds)*int64(time.Second) - 4},
	} {
		if got := pacingNanoseconds(test.offset, rate); got != test.wanted {
			t.Fatalf("offset=%d: wanted %d ns, got %d", test.offset, test.wanted, got)
		}
	}
	for _, mbps := range []int{1000, 1001, 2000, 2001} {
		// The invalid literal stops accepted arguments before any network I/O.
		err := runClient("not-a-peer", "tcp", "both", 60, 64, mbps, "", "", "", "")
		wanted := "literal control peer required"
		if mbps > 2000 {
			wanted = "invalid workload"
		}
		if err == nil || err.Error() != wanted {
			t.Fatalf("mbps=%d: wanted %q, got %v", mbps, wanted, err)
		}
	}
}

type fixtureTimeout struct{}

func (fixtureTimeout) Error() string   { return "private-timeout-marker" }
func (fixtureTimeout) Timeout() bool   { return true }
func (fixtureTimeout) Temporary() bool { return true }

type failingConn struct {
	net.Conn
	err error
}

func (c failingConn) Read([]byte) (int, error)         { return 0, c.err }
func (c failingConn) Write([]byte) (int, error)        { return 0, c.err }
func (c failingConn) SetReadDeadline(time.Time) error  { return nil }
func (c failingConn) SetWriteDeadline(time.Time) error { return nil }

func TestIOErrorKindsAreFixedAndIgnorePrivateOperationContext(t *testing.T) {
	cases := []struct {
		err  error
		kind string
	}{
		{nil, ""},
		{fixtureTimeout{}, "timeout"},
		{io.EOF, "eof"},
		{io.ErrUnexpectedEOF, "unexpected-eof"},
		{syscall.ECONNRESET, "connection-reset"},
		{syscall.EPIPE, "broken-pipe"},
		{io.ErrShortWrite, "short-write"},
		{net.ErrClosed, "closed"},
		{io.ErrNoProgress, "no-progress"},
		{errPacketSourceSize, "datagram-source-or-size"},
		{errDatagramSize, "datagram-source-or-size"},
		{errors.New("private-unknown-marker"), "other-io"},
	}
	for _, current := range cases {
		actual := ioErrorKind(current.err)
		if actual != current.kind {
			t.Fatalf("expected fixed class %q, got %q", current.kind, actual)
		}
		if current.err != nil {
			wrapped := &net.OpError{Op: "read", Net: "unix",
				Addr: &net.UnixAddr{Name: "/private-control-marker.sock", Net: "unix"},
				Err:  fmt.Errorf("private-wrapper-marker: %w", current.err)}
			if ioErrorKind(wrapped) != current.kind {
				t.Fatalf("wrapped operation lost class %q", current.kind)
			}
		}
	}
}

func TestTransferFailuresKeepClassAndIncorrectPayloadVerdictWithoutEndpoints(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		for _, sending := range []bool{false, true} {
			r := request{Transport: transport, Seconds: 1, BytesPerSecond: int64(frameSize(request{Transport: transport})), Seed: 7}
			err := &net.OpError{Op: "read", Net: "unix",
				Addr: &net.UnixAddr{Name: "/private-control-marker.sock", Net: "unix"}, Err: fixtureTimeout{}}
			out := transfer(failingConn{err: err}, r, sending)
			if out.Error == "" || out.ErrorKind != "timeout" || out.Bytes != 0 || out.Packets != 0 {
				t.Fatalf("%s sending=%v changed failure classification: %+v", transport, sending, out)
			}
			if checkedFlow("up", r, out, out, true).Error == "" {
				t.Fatal("classified error incorrectly accepted incomplete payload")
			}
			encoded, encodeErr := json.Marshal(out)
			if encodeErr != nil || bytes.Contains(encoded, []byte("private-")) {
				t.Fatalf("result retained private operation context: %s", encoded)
			}
		}
	}
}

func TestMixedWorkloadKeepsBothTransportsBidirectional(t *testing.T) {
	for _, flows := range []int{64, 128, 256, 512} {
		counts := make(map[string]int)
		for index := 0; index < flows; index++ {
			kind, direction := flowKindDirection("mixed", "both", index, flows, false)
			counts[kind+"/"+direction]++
		}
		for _, key := range []string{"tcp/up", "tcp/down", "udp/up", "udp/down"} {
			if counts[key] != flows/4 {
				t.Fatalf("%d flows lost prescribed direction %s: %v", flows, key, counts)
			}
		}
	}
}

func TestWorkloadAllowsTheBoundedFlowCapacityWithoutDiagnosticFlags(t *testing.T) {
	if udpPacingCredit != 16 {
		t.Fatal("ordinary workload changed the fixed pacing credit")
	}
	for _, flows := range []int{64, 128, 256, 512, 514} {
		err := runClient("not-a-peer", "mixed", "both", 60, flows, 1000, "", "", "", "")
		wanted := "literal control peer required"
		if flows > 512 {
			wanted = "invalid workload"
		}
		if err == nil || !strings.Contains(err.Error(), wanted) {
			t.Fatalf("flows=%d: expected %q, got %v", flows, wanted, err)
		}
	}
}
