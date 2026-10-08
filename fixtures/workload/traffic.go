// Bounded, native traffic generator/validator. This is a test origin, never a
// proxy implementation. The origin can run only in a harness-owned Linux guest.
// Only application payload records count; control connections do not.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type request struct {
	Transport       string `json:"transport"`
	Direction       string `json:"direction"`
	Seconds         int    `json:"seconds"`
	BytesPerSecond  int64  `json:"bytes_per_second"`
	Seed            uint64 `json:"seed"`
	ExpectedSource  string `json:"expected_source,omitempty"`
	TargetHost      string `json:"-"`
	TargetIP        string `json:"-"`
	Probe           bool   `json:"probe,omitempty"`
	InitialHello    bool   `json:"initial_hello,omitempty"`
	ProbeRounds     int    `json:"probe_rounds,omitempty"`
	UDPDestinations int    `json:"udp_destinations,omitempty"`
}
type result struct {
	Bytes     int64   `json:"bytes"`
	Packets   int64   `json:"packets"`
	Elapsed   float64 `json:"seconds"`
	Digest    string  `json:"sha256,omitempty"`
	Reordered int64   `json:"reordered"`
	Windows   []int64 `json:"bytes_per_second"`
	Error     string  `json:"error,omitempty"`
	ErrorKind string  `json:"error_kind,omitempty"`
}

type flowResult struct {
	Transport      string `json:"transport"`
	Direction      string `json:"direction"`
	Sent           result `json:"sent"`
	Received       result `json:"received"`
	Error          string `json:"error,omitempty"`
	SourceVerified bool   `json:"source_verified"`
	SetupErrorKind string `json:"setup_error_kind,omitempty"`
}

type flowReadyAck struct {
	Ready          bool `json:"ready"`
	SourceVerified bool `json:"source_verified"`
}

type duplexResult struct {
	Up   result `json:"up"`
	Down result `json:"down"`
}

var (
	errPacketSourceSize = errors.New("packet source/size")
	errDatagramSize     = errors.New("oversized datagram")
	errBarrierTimeout   = errors.New("start barrier timed out")
	errBarrierReadyIO   = errors.New("start barrier ready_io")
	errBarrierReadIO    = errors.New("start barrier read_io")
	errBarrierInvalid   = errors.New("invalid start barrier")
	errKernelDNSOrigin  = errors.New("TUN DNS origin mismatch")
)

const startBarrierWait = 15 * time.Second

// Only fixed classifications may survive into text conclusions. In particular,
// net.OpError strings can contain peer addresses and local Unix control paths.
func ioErrorKind(err error) string {
	if err == nil {
		return ""
	}
	for cause := err; cause != nil; cause = errors.Unwrap(cause) {
		if networkError, ok := cause.(net.Error); ok && networkError.Timeout() {
			return "timeout"
		}
	}
	switch {
	case errors.Is(err, io.EOF):
		return "eof"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "unexpected-eof"
	case errors.Is(err, syscall.ECONNRESET):
		return "connection-reset"
	case errors.Is(err, syscall.EPIPE):
		return "broken-pipe"
	case errors.Is(err, io.ErrShortWrite):
		return "short-write"
	case errors.Is(err, net.ErrClosed):
		return "closed"
	case errors.Is(err, io.ErrNoProgress):
		return "no-progress"
	case errors.Is(err, errPacketSourceSize), errors.Is(err, errDatagramSize):
		return "datagram-source-or-size"
	default:
		return "other-io"
	}
}

// Setup retry policy must distinguish unavailable endpoints from corrupt DNS.
func setupErrorKind(err error) string {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "connection-refused"
	}
	if errors.Is(err, errKernelDNSOrigin) {
		return "dns-origin-mismatch"
	}
	return ioErrorKind(err)
}

func frameSize(r request) int {
	if r.Probe {
		return 32
	}
	if r.Transport == "udp" {
		return 1200
	}
	return 65536
}
func count(r request) int64 {
	if r.Probe {
		return int64(r.ProbeRounds)
	}
	return r.BytesPerSecond * int64(r.Seconds) / int64(frameSize(r))
}

func payloadSize(r request, _ int64) int { return frameSize(r) }

func totalBytes(r request) int64 { return count(r) * int64(frameSize(r)) }

func validate(r request) error {
	if (r.Transport != "tcp" && r.Transport != "udp") ||
		(r.Direction != "up" && r.Direction != "down" && r.Direction != "both") || r.Seconds < 1 || r.Seconds > 1800 ||
		r.BytesPerSecond < 1 || r.BytesPerSecond > maxAggregateBytesPerSecond || count(r) == 0 {
		return errors.New("invalid bounded workload")
	}
	if r.UDPDestinations < 0 || r.UDPDestinations > 256 ||
		(r.UDPDestinations > 1 && (r.Transport != "udp" || r.Probe)) {
		return errors.New("invalid fixture UDP destination count")
	}
	if r.Probe && (r.ProbeRounds < 1 || r.ProbeRounds > 100 || r.Seconds != (r.ProbeRounds+19)/20) {
		return errors.New("invalid probe count")
	}
	return nil
}

func pattern(buf []byte, seq, seed uint64) {
	binary.LittleEndian.PutUint64(buf, seq)
	for i := 8; i < len(buf); i += 8 {
		binary.LittleEndian.PutUint64(buf[i:], seq^seed^uint64(i)*0x9e3779b97f4a7c15)
	}
}
func check(buf []byte, seed uint64) bool {
	seq := binary.LittleEndian.Uint64(buf)
	for i := 8; i < len(buf); i += 8 {
		if binary.LittleEndian.Uint64(buf[i:]) != seq^seed^uint64(i)*0x9e3779b97f4a7c15 {
			return false
		}
	}
	return true
}
func writeAll(conn net.Conn, buf []byte) error {
	for len(buf) > 0 {
		n, err := conn.Write(buf)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		buf = buf[n:]
	}
	return nil
}
func pace(deadline time.Time) {
	if delay := time.Until(deadline); delay > 0 {
		time.Sleep(delay)
	}
}

func pacingNanoseconds(offset, bytesPerSecond int64) int64 {
	// Split before multiplying: even a validated 1,800-second, 2 Gbps
	// workload has an offset whose direct nanosecond product overflows.
	return offset/bytesPerSecond*int64(time.Second) +
		offset%bytesPerSecond*int64(time.Second)/bytesPerSecond
}

type udpSendJob struct {
	conn  net.Conn
	r     request
	done  chan result
	out   result
	start time.Time
	buf   [1200]byte
}

// The external client and origin share this capacity, including the 512-flow
// workload plus bounded witnesses. It is not a measured core queue or quota.
const maxUDPJobs = 1024
const maxAggregateMbps = 2000
const maxAggregateBytesPerSecond int64 = maxAggregateMbps * 125000

var udpJobs = make(chan *udpSendJob, maxUDPJobs)
var udpOnce sync.Once

const udpPacingCredit = 16

var udpDestinations = 1

var probeMode bool
var probeRounds int

// One process-local pacer owns all UDP sends. Per-flow timers otherwise wake
// together and repay arbitrary scheduling delays as bursts into the proxy.
// This queue holds bounded flow jobs, never a growing queue of datagrams.
func udpSender() {
	runUDPSender(udpJobs)
}

// A closed test input drains every already-admitted job before returning. The
// production fixture channel stays open for the lifetime of its owned process.
func runUDPSender(pending <-chan *udpSendJob) (peak int) {
	jobs := make([]*udpSendJob, 0, maxUDPJobs)
	var due time.Time
	var rate int64
	var period time.Duration
	index := 0
	for {
		if len(jobs) == 0 {
			if pending == nil {
				return
			}
			job, ok := <-pending
			if !ok {
				return
			}
			jobs = append(jobs, job)
			rate = job.r.BytesPerSecond
			period = time.Duration(1200 * int64(time.Second) / rate)
			if peak == 0 {
				peak = 1
			}
			due = time.Now()
			index = 0
		}
		select {
		case job, ok := <-pending:
			// Round-robin is exact for this driver's equal-rate flows only.
			if !ok {
				pending = nil
			} else if len(jobs) >= maxUDPJobs || job.r.BytesPerSecond != jobs[0].r.BytesPerSecond || rate+job.r.BytesPerSecond > maxAggregateBytesPerSecond {
				job.done <- result{Error: "UDP aggregate workload exceeds bound", ErrorKind: "workload-bound"}
			} else {
				jobs = append(jobs, job)
				if len(jobs) > peak {
					peak = len(jobs)
				}
				rate += job.r.BytesPerSecond
				period = time.Duration(1200 * int64(time.Second) / rate)
			}
		default:
		}
		// Equal-rate jobs only change the aggregate pacing period when a
		// flow joins or leaves, not for every packet in the active set.
		// At most 16 records of timing credit. Discard excess credit, not
		// payload: all prescribed records still have to arrive within the
		// independently checked 1% timing/goodput bounds to pass.
		if earliest := time.Now().Add(-time.Duration(udpPacingCredit) * period); earliest.After(due) {
			due = earliest
		}
		if delay := time.Until(due); delay > 100*time.Microsecond {
			time.Sleep(delay - 50*time.Microsecond)
		}
		// A single external-driver thread handles the sub-timer-resolution
		// tail. No per-packet lock or one busy-waiting thread per flow.
		for time.Now().Before(due) {
		}
		job := jobs[index]
		now := time.Now()
		if job.start.IsZero() {
			job.start = now
		}
		payload := job.buf[:payloadSize(job.r, job.out.Packets)]
		pattern(payload, uint64(job.out.Packets), job.r.Seed)
		n, err := job.conn.Write(payload)
		if err != nil || n != len(payload) {
			job.out.Error = "send failed"
			if err == nil {
				err = io.ErrShortWrite
			}
			job.out.ErrorKind = ioErrorKind(err)
		} else {
			job.out.Packets++
			job.out.Bytes += int64(n)
			window := int(time.Since(job.start) / time.Second)
			if window >= len(job.out.Windows) {
				job.out.Error = "unbounded drain"
				job.out.ErrorKind = "drain-bound"
			} else {
				job.out.Windows[window] += int64(n)
			}
		}
		finished := job.out.Error != "" || job.out.Packets == count(job.r)
		if finished {
			job.out.Elapsed = time.Since(job.start).Seconds()
			job.done <- job.out
			rate -= job.r.BytesPerSecond
			copy(jobs[index:], jobs[index+1:])
			jobs[len(jobs)-1] = nil
			jobs = jobs[:len(jobs)-1]
		} else {
			index++
		}
		if index >= len(jobs) {
			index = 0
		}
		due = due.Add(period)
		// Advance the just-sent packet by its original period before
		// adopting the smaller remaining workload's period for the next.
		if finished && rate > 0 {
			period = time.Duration(1200 * int64(time.Second) / rate)
		}
	}
}

func sendUDP(conn net.Conn, r request) result {
	udpOnce.Do(func() { go udpSender() })
	job := &udpSendJob{conn: conn, r: r, done: make(chan result, 1), out: result{Windows: make([]int64, r.Seconds+3)}}
	conn.SetWriteDeadline(time.Now().Add(time.Duration(r.Seconds+3) * time.Second))
	defer conn.SetWriteDeadline(time.Time{})
	udpJobs <- job
	return <-job.done
}

func transfer(conn net.Conn, r request, send bool) result {
	if send && r.Transport == "udp" && !r.Probe {
		return sendUDP(conn, r)
	}
	size, total := frameSize(r), count(r)
	buf := make([]byte, size)
	bitmap := make([]byte, (total+7)/8)
	digest := sha256.New()
	out := result{Windows: make([]int64, r.Seconds+3)}
	start := time.Now()
	setDeadline := conn.SetReadDeadline
	if send {
		setDeadline = conn.SetWriteDeadline
	}
	setDeadline(start.Add(time.Duration(r.Seconds+3) * time.Second))
	defer setDeadline(time.Time{})
	highest := int64(-1)
	for seq := int64(0); seq < total; seq++ {
		actualSize := payloadSize(r, seq)
		if send {
			offset := seq * int64(size)
			nanoseconds := pacingNanoseconds(offset, r.BytesPerSecond)
			due := start.Add(time.Duration(nanoseconds))
			pace(due)
			pattern(buf[:actualSize], uint64(seq), r.Seed)
			if err := writeAll(conn, buf[:actualSize]); err != nil {
				out.Error = "send failed"
				out.ErrorKind = ioErrorKind(err)
				break
			}
		} else {
			var n int
			var err error
			if r.Transport == "tcp" {
				n, err = io.ReadFull(conn, buf)
			} else {
				n, err = conn.Read(buf)
			}
			if err != nil || n < 8 {
				out.Error = "receive incomplete"
				out.ErrorKind = ioErrorKind(err)
				if err == nil {
					out.ErrorKind = "short-record"
				}
				break
			}
			id := binary.LittleEndian.Uint64(buf)
			if id >= uint64(total) || n != payloadSize(r, int64(id)) || !check(buf[:n], r.Seed) {
				out.Error = "payload corruption"
				out.ErrorKind = "payload-corruption"
				break
			}
			if r.Transport == "tcp" && id != uint64(seq) {
				out.Error = "TCP sequence mismatch"
				out.ErrorKind = "sequence-mismatch"
				break
			}
			index, bit := id/8, byte(1<<(id%8))
			if bitmap[index]&bit != 0 {
				out.Error = "duplicate datagram"
				out.ErrorKind = "duplicate-datagram"
				break
			}
			bitmap[index] |= bit
			actualSize = n
			if int64(id) < highest {
				out.Reordered++
			} else {
				highest = int64(id)
			}
		}
		if r.Transport == "tcp" {
			digest.Write(buf)
		}
		out.Bytes += int64(actualSize)
		out.Packets++
		window := int(time.Since(start) / time.Second)
		if window >= len(out.Windows) {
			out.Error = "unbounded drain"
			out.ErrorKind = "drain-bound"
			break
		}
		out.Windows[window] += int64(actualSize)
	}
	out.Elapsed = time.Since(start).Seconds()
	if r.Transport == "tcp" {
		out.Digest = hex.EncodeToString(digest.Sum(nil))
	}
	return out
}

// Two independent payload sequences share one TCP connection. Directional
// deadlines keep a completed sender from clearing the receiver's drain bound.
func transferDuplex(conn net.Conn, r request, client bool) duplexResult {
	up := make(chan result, 1)
	upRequest, downRequest := r, r
	upRequest.Direction, downRequest.Direction = "up", "down"
	downRequest.Seed ^= 0xd6e8feb86659fd93
	go func() { up <- transfer(conn, upRequest, client) }()
	down := transfer(conn, downRequest, !client)
	return duplexResult{Up: <-up, Down: down}
}

// A connected packet adapter for the server; first datagram pins the peer.
// Read uses a one-byte surplus so oversized packets cannot be silently accepted.
type packetConn struct {
	*net.UDPConn
	peer    netip.AddrPort
	scratch [1463]byte
}

func (c *packetConn) Read(buf []byte) (int, error) {
	n, from, err := c.ReadFromUDPAddrPort(c.scratch[:])
	if err != nil {
		return 0, err
	}
	if from != c.peer || n > len(buf) {
		return 0, errPacketSourceSize
	}
	return copy(buf, c.scratch[:n]), nil
}
func (c *packetConn) Write(buf []byte) (int, error) { return c.WriteToUDPAddrPort(buf, c.peer) }
func (c *packetConn) RemoteAddr() net.Addr          { return net.UDPAddrFromAddrPort(c.peer) }

// These optional adapters belong only to the external pressure fixture. Each
// client retains one UDP socket/source port while exercising distinct target
// ports; no origin reader, buffer or socket is part of the measured core PID.
type datagramSocket interface {
	ReadFromUDPAddrPort([]byte) (int, netip.AddrPort, error)
	WriteToUDPAddrPort([]byte, netip.AddrPort) (int, error)
	LocalAddr() net.Addr
	Close() error
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

type cyclingPacketConn struct {
	datagramSocket
	peers   []netip.AddrPort
	allowed map[netip.AddrPort]struct{}
	next    int
	scratch [1463]byte
}

func (c *cyclingPacketConn) Read(buf []byte) (int, error) {
	n, peer, err := c.ReadFromUDPAddrPort(c.scratch[:])
	if err != nil {
		return 0, err
	}
	if _, ok := c.allowed[peer]; !ok || n > len(buf) {
		return 0, errPacketSourceSize
	}
	return copy(buf, c.scratch[:n]), nil
}
func (c *cyclingPacketConn) Write(buf []byte) (int, error) {
	peer := c.peers[c.next]
	c.next = (c.next + 1) % len(c.peers)
	return c.WriteToUDPAddrPort(buf, peer)
}
func (c *cyclingPacketConn) RemoteAddr() net.Addr { return net.UDPAddrFromAddrPort(c.peers[0]) }

type originPacket struct {
	buf [1463]byte
	n   int
	err error
}
type originPortsConn struct {
	sockets []datagramSocket
	peers   []netip.AddrPort
	packets chan originPacket
	done    chan struct{}
	readers sync.WaitGroup
	closed  sync.Once
	next    int
}

func newOriginPortsConn(sockets []datagramSocket, peers []netip.AddrPort) *originPortsConn {
	c := &originPortsConn{sockets: sockets, peers: peers,
		packets: make(chan originPacket, len(sockets)), done: make(chan struct{})}
	for index, socket := range sockets {
		c.readers.Add(1)
		go func(index int, socket datagramSocket) {
			defer c.readers.Done()
			var packet originPacket
			for {
				var peer netip.AddrPort
				packet.n, peer, packet.err = socket.ReadFromUDPAddrPort(packet.buf[:])
				if packet.err == nil && peer != c.peers[index] {
					packet.err = errPacketSourceSize
				}
				select {
				case c.packets <- packet:
				case <-c.done:
					return
				}
				if packet.err != nil {
					return
				}
			}
		}(index, socket)
	}
	return c
}
func (c *originPortsConn) Read(buf []byte) (int, error) {
	select {
	case packet := <-c.packets:
		if packet.err != nil {
			return 0, packet.err
		}
		if packet.n > len(buf) {
			return 0, errPacketSourceSize
		}
		return copy(buf, packet.buf[:packet.n]), nil
	case <-c.done:
		return 0, net.ErrClosed
	}
}
func (c *originPortsConn) Write(buf []byte) (int, error) {
	index := c.next
	c.next = (c.next + 1) % len(c.sockets)
	return c.sockets[index].WriteToUDPAddrPort(buf, c.peers[index])
}
func (c *originPortsConn) Close() error {
	c.closed.Do(func() {
		close(c.done)
		for _, socket := range c.sockets {
			socket.Close()
		}
		c.readers.Wait()
	})
	return nil
}
func (c *originPortsConn) LocalAddr() net.Addr  { return c.sockets[0].LocalAddr() }
func (c *originPortsConn) RemoteAddr() net.Addr { return net.UDPAddrFromAddrPort(c.peers[0]) }
func (c *originPortsConn) SetDeadline(t time.Time) error {
	for _, socket := range c.sockets {
		if err := socket.SetDeadline(t); err != nil {
			return err
		}
	}
	return nil
}
func (c *originPortsConn) SetReadDeadline(t time.Time) error {
	for _, socket := range c.sockets {
		if err := socket.SetReadDeadline(t); err != nil {
			return err
		}
	}
	return nil
}
func (c *originPortsConn) SetWriteDeadline(t time.Time) error {
	for _, socket := range c.sockets {
		if err := socket.SetWriteDeadline(t); err != nil {
			return err
		}
	}
	return nil
}

func serveFlow(control net.Conn) {
	defer control.Close()
	control.SetDeadline(time.Now().Add(15 * time.Second))
	decoder, encoder := json.NewDecoder(io.LimitReader(control, 8192)), json.NewEncoder(control)
	var r request
	if decoder.Decode(&r) != nil || validate(r) != nil {
		return
	}
	control.SetDeadline(time.Now().Add(time.Duration(r.Seconds+30) * time.Second))
	var data net.Conn
	var listener net.Listener
	var udp *net.UDPConn
	var extraPorts []*net.UDPConn
	var err error
	var port int
	if r.Transport == "tcp" {
		network, bind := "tcp4", "0.0.0.0:0"
		if control.LocalAddr().(*net.TCPAddr).IP.To4() == nil {
			network, bind = "tcp6", "[::]:0"
		}
		listener, err = net.Listen(network, bind)
		if err != nil {
			return
		}
		defer listener.Close()
		listener.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second))
		port = listener.Addr().(*net.TCPAddr).Port
	} else {
		network := "udp4"
		if control.LocalAddr().(*net.TCPAddr).IP.To4() == nil {
			network = "udp6"
		}
		udp, err = net.ListenUDP(network, &net.UDPAddr{})
		if err != nil {
			return
		}
		defer udp.Close()
		port = udp.LocalAddr().(*net.UDPAddr).Port
		for index := 1; index < r.UDPDestinations; index++ {
			extra, err := net.ListenUDP(network, &net.UDPAddr{})
			if err != nil {
				return
			}
			defer extra.Close()
			extraPorts = append(extraPorts, extra)
		}
	}
	answer := struct {
		Port  int   `json:"port"`
		Ports []int `json:"ports,omitempty"`
	}{Port: port}
	if len(extraPorts) > 0 {
		answer.Ports = append(answer.Ports, port)
		for _, extra := range extraPorts {
			answer.Ports = append(answer.Ports, extra.LocalAddr().(*net.UDPAddr).Port)
		}
	}
	if encoder.Encode(answer) != nil {
		return
	}
	if listener != nil {
		data, err = listener.Accept()
		if err != nil {
			return
		}
		defer data.Close()
		if r.InitialHello {
			data.SetReadDeadline(time.Now().Add(10 * time.Second))
			var hello [1]byte
			if _, err := io.ReadFull(data, hello[:]); err != nil || hello[0] != 42 {
				return
			}
			data.SetReadDeadline(time.Time{})
		}
	} else {
		udp.SetReadDeadline(time.Now().Add(10 * time.Second))
		var hello [2]byte
		n, peer, e := udp.ReadFromUDPAddrPort(hello[:])
		if e != nil || n != 1 || hello[0] != 42 {
			return
		}
		data = &packetConn{UDPConn: udp, peer: peer}
		if len(extraPorts) > 0 {
			sockets := []datagramSocket{udp}
			peers := []netip.AddrPort{peer}
			deadline := time.Now().Add(10 * time.Second)
			for _, extra := range extraPorts {
				extra.SetReadDeadline(deadline)
				n, nextPeer, err := extra.ReadFromUDPAddrPort(hello[:])
				if err != nil || n != 1 || hello[0] != 42 || nextPeer.Addr() != peer.Addr() {
					return
				}
				sockets, peers = append(sockets, extra), append(peers, nextPeer)
			}
			data = newOriginPortsConn(sockets, peers)
			data.SetReadDeadline(time.Time{})
			defer data.Close()
		}
	}
	sourceVerified := false
	if r.ExpectedSource != "" {
		source, _, e := net.SplitHostPort(data.RemoteAddr().String())
		sourceVerified = e == nil && net.ParseIP(source).Equal(net.ParseIP(r.ExpectedSource))
		if !sourceVerified {
			encoder.Encode(map[string]bool{"ready": false, "source_verified": false})
			return
		}
	}
	if encoder.Encode(flowReadyAck{Ready: true, SourceVerified: sourceVerified}) != nil {
		return
	}
	var start string
	if decoder.Decode(&start) != nil || start != "start" {
		return
	}
	if r.Direction == "both" {
		encoder.Encode(transferDuplex(data, r, false))
	} else {
		encoder.Encode(transfer(data, r, r.Direction == "down"))
	}
}

func origin() error {
	if runtime.GOOS != "linux" || os.Getenv("BENCHMARK_ISOLATED") != "1" {
		return errors.New("origin requires an owned isolated Linux container")
	}
	listener, err := net.Listen("tcp", ":24003")
	if err != nil {
		return err
	}
	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go serveFlow(conn)
	}
}

func kernelDNSQuestion(name, expected string) ([]byte, []byte, error) {
	address := net.ParseIP(expected)
	if address == nil {
		return nil, nil, errors.New("literal controlled DNS origin required")
	}
	query := []byte{0x07, 0xea, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if len(label) < 1 || len(label) > 63 {
			return nil, nil, errors.New("invalid controlled name")
		}
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	qtype := byte(1)
	ip := address.To4()
	if ip == nil {
		qtype = 28
		ip = address.To16()
	}
	query = append(query, 0, 0, qtype, 0, 1)
	return query, ip, nil
}

func validKernelDNSReply(query, reply, ip []byte) bool {
	if len(query) < 12 || len(reply) < len(query)+12+len(ip) {
		return false
	}
	// A recursive forwarder and an authoritative controlled server may set
	// AA/RA differently. Require the same successful standard response, ID,
	// question and literal origin rather than one resolver's flag combination.
	flags := binary.BigEndian.Uint16(reply[2:4])
	expected := uint16(0x8000) | binary.BigEndian.Uint16(query[2:4])&0x0100
	return bytes.Equal(reply[:2], query[:2]) && flags & ^uint16(0x0480) == expected &&
		bytes.Equal(reply[4:8], []byte{0, 1, 0, 1}) &&
		bytes.Equal(reply[12:len(query)], query[12:]) && bytes.HasSuffix(reply, ip)
}

func kernelResolve(name, expected string) error {
	query, ip, err := kernelDNSQuestion(name, expected)
	if err != nil {
		return err
	}
	conn, err := net.DialTimeout("udp", "198.18.0.1:53", 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(query); err != nil {
		return err
	}
	reply := make([]byte, 1452)
	n, err := conn.Read(reply)
	if err != nil {
		return err
	}
	reply = reply[:n]
	if !validKernelDNSReply(query, reply, ip) {
		return errKernelDNSOrigin
	}
	return nil
}

type boundedUDP struct {
	net.Conn
	scratch [1201]byte
}

func (c *boundedUDP) Read(buf []byte) (int, error) {
	n, err := c.Conn.Read(c.scratch[:])
	if err != nil {
		return 0, err
	}
	if n > len(buf) {
		return 0, errDatagramSize
	}
	return copy(buf, c.scratch[:n]), nil
}

// Only native Linux kernel sockets enter the shared real-TUN workload.
func dialData(r request, target string) (net.Conn, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("real TUN requires native Linux kernel sockets")
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, errors.New("invalid real TUN target")
	}
	if net.ParseIP(host) == nil {
		if err := kernelResolve(host, r.TargetIP); err != nil {
			return nil, err
		}
		target = net.JoinHostPort(r.TargetIP, port)
	}
	conn, err := net.DialTimeout(r.Transport, target, 5*time.Second)
	if err != nil {
		return nil, err
	}
	if r.Transport == "udp" {
		return &boundedUDP{Conn: conn}, nil
	}
	if err := writeAll(conn, []byte{42}); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func dialCyclingUDP(r request, ports []int) (*cyclingPacketConn, error) {
	if runtime.GOOS != "linux" || len(ports) != r.UDPDestinations {
		return nil, errors.New("multi-destination UDP requires the Linux real-TUN fixture")
	}
	if r.TargetHost != "" {
		if err := kernelResolve(r.TargetHost, r.TargetIP); err != nil {
			return nil, err
		}
	}
	ip, err := netip.ParseAddr(r.TargetIP)
	if err != nil {
		return nil, errors.New("invalid literal UDP peer")
	}
	ip = ip.Unmap()
	network := "udp4"
	if ip.Is6() {
		network = "udp6"
	}
	socket, err := net.ListenUDP(network, &net.UDPAddr{})
	if err != nil {
		return nil, err
	}
	c := &cyclingPacketConn{datagramSocket: socket, allowed: make(map[netip.AddrPort]struct{}, len(ports))}
	for _, port := range ports {
		if port < 1 || port > 65535 {
			socket.Close()
			return nil, errors.New("invalid destination port")
		}
		peer := netip.AddrPortFrom(ip, uint16(port))
		if _, exists := c.allowed[peer]; exists {
			socket.Close()
			return nil, errors.New("duplicate destination port")
		}
		c.peers = append(c.peers, peer)
		c.allowed[peer] = struct{}{}
	}
	return c, nil
}

func setFlowControlDeadline(control net.Conn, seconds int) error {
	return control.SetDeadline(time.Now().Add(time.Duration(seconds+15) * time.Second))
}

func clientFlow(peer string, r request, ready *sync.WaitGroup, start <-chan struct{}) []flowResult {
	outcome := flowResult{Transport: r.Transport, Direction: r.Direction}
	signaled := false
	defer func() {
		if !signaled {
			ready.Done()
		}
	}()
	fail := func(message string) []flowResult { outcome.Error = message; return []flowResult{outcome} }
	failSetup := func(message string, err error) []flowResult {
		outcome.SetupErrorKind = setupErrorKind(err)
		return fail(message)
	}
	control, err := net.DialTimeout("tcp", peer, 5*time.Second)
	if err != nil {
		return failSetup("control connect", err)
	}
	defer control.Close()
	setFlowControlDeadline(control, r.Seconds)
	decoder, encoder := json.NewDecoder(io.LimitReader(control, 65536)), json.NewEncoder(control)
	if encoder.Encode(r) != nil {
		return fail("control request")
	}
	var answer struct {
		Port  int   `json:"port"`
		Ports []int `json:"ports"`
	}
	if decoder.Decode(&answer) != nil || answer.Port < 1 {
		return fail("data port")
	}
	host, _, _ := net.SplitHostPort(peer)
	r.TargetIP = host
	if r.TargetHost != "" {
		host = r.TargetHost
	}
	var data net.Conn
	if r.UDPDestinations > 1 {
		data, err = dialCyclingUDP(r, answer.Ports)
	} else {
		data, err = dialData(r, net.JoinHostPort(host, strconv.Itoa(answer.Port)))
	}
	if err != nil {
		return failSetup("data connect", err)
	}
	defer data.Close()
	var ack flowReadyAck
	if r.Transport == "udp" {
		for index := 0; index < max(1, r.UDPDestinations); index++ {
			if _, err = data.Write([]byte{42}); err != nil {
				return fail("UDP hello")
			}
			if r.UDPDestinations > 1 {
				time.Sleep(time.Millisecond)
			}
		}
	}
	if err := decoder.Decode(&ack); err != nil {
		return failSetup("data readiness", err)
	}
	if !ack.Ready {
		if r.ExpectedSource != "" && !ack.SourceVerified {
			return fail("missing origin route witness")
		}
		return fail("data readiness")
	}
	outcome.SourceVerified = ack.SourceVerified
	if r.ExpectedSource != "" && !ack.SourceVerified {
		return fail("missing origin route witness")
	}
	ready.Done()
	signaled = true
	<-start
	// Setup/barrier waiting must not consume the unchanged load/control budget.
	if setFlowControlDeadline(control, r.Seconds) != nil {
		return fail("control deadline")
	}
	if encoder.Encode("start") != nil {
		return fail("start")
	}
	if r.Direction == "both" {
		local := transferDuplex(data, r, true)
		var remote duplexResult
		if decoder.Decode(&remote) != nil {
			return fail("remote counters")
		}
		return []flowResult{
			checkedFlow("up", r, local.Up, remote.Up, ack.SourceVerified),
			checkedFlow("down", r, remote.Down, local.Down, ack.SourceVerified),
		}
	}
	local := transfer(data, r, r.Direction == "up")
	var remote result
	if decoder.Decode(&remote) != nil {
		return fail("remote counters")
	}
	if r.Direction == "up" {
		outcome.Sent, outcome.Received = local, remote
	} else {
		outcome.Sent, outcome.Received = remote, local
	}
	return []flowResult{checkedFlow(r.Direction, r, outcome.Sent, outcome.Received, ack.SourceVerified)}
}

func checkedFlow(direction string, r request, sent, received result, sourceVerified bool) flowResult {
	outcome := flowResult{Transport: r.Transport, Direction: direction, Sent: sent, Received: received, SourceVerified: sourceVerified}
	expected := totalBytes(r)
	if outcome.Sent.Error != "" || outcome.Received.Error != "" || outcome.Sent.Bytes != expected ||
		outcome.Received.Bytes != expected || outcome.Sent.Digest != outcome.Received.Digest {
		outcome.Error = "incomplete or incorrect payload"
	}
	return outcome
}

func startBarrier(readyFile, startFile string, flows int) error {
	if readyFile == "" && startFile == "" {
		return nil
	}
	if readyFile == "" || startFile == "" || readyFile == startFile {
		return errBarrierInvalid
	}
	ready, err := os.OpenFile(readyFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errBarrierReadyIO
	}
	err = json.NewEncoder(ready).Encode(map[string]int{"pid": os.Getpid(), "flows": flows})
	closeErr := ready.Close()
	if err != nil || closeErr != nil {
		return errBarrierReadyIO
	}
	return awaitStartBarrier(startFile, time.Now().Add(startBarrierWait))
}

func awaitStartBarrier(startFile string, deadline time.Time) error {
	for time.Now().Before(deadline) {
		start, err := os.Open(startFile)
		if err == nil {
			data, readErr := io.ReadAll(io.LimitReader(start, 16))
			start.Close()
			if readErr != nil {
				return errBarrierReadIO
			}
			if string(data) == "start\n" {
				return nil
			}
			if len(data) >= len("start\n") {
				return errBarrierInvalid
			}
		} else if !os.IsNotExist(err) {
			return errBarrierReadIO
		}
		time.Sleep(time.Millisecond)
	}
	return errBarrierTimeout
}

func flowKindDirection(transport, direction string, index, flows int, duplex bool) (string, string) {
	kind, way := transport, direction
	if transport == "mixed" {
		kind = "tcp"
		if index >= flows/2 {
			kind = "udp"
		}
	}
	if direction == "both" && !duplex {
		down := index >= flows/2
		if transport == "mixed" {
			// Both transports get equal up/down flows and bandwidth.
			down = index%(flows/2) >= flows/4
		}
		way = "up"
		if down {
			way = "down"
		}
	}
	return kind, way
}

func runClient(peer, transport, direction string, seconds, flows, mbps int, target, source, readyFile, startFile string) error {
	duplex := probeMode
	if (direction != "up" && direction != "down" && direction != "both") || flows < 1 || flows > 512 ||
		(direction == "both" && flows%2 != 0 && !duplex) || mbps < 1 || mbps > maxAggregateMbps {
		return errors.New("invalid workload")
	}
	if udpDestinations < 1 || udpDestinations > 256 ||
		(udpDestinations > 1 && (probeMode || transport == "tcp")) {
		return errors.New("invalid multi-destination fixture workload")
	}
	peerHost, _, peerErr := net.SplitHostPort(peer)
	peerIP := net.ParseIP(peerHost)
	if peerErr != nil || peerIP == nil {
		return errors.New("literal control peer required")
	}
	r := request{Transport: transport, Direction: "up", Seconds: seconds, BytesPerSecond: int64(mbps) * 125000 / int64(flows), Seed: 20260929}
	if transport == "mixed" {
		if flows%2 != 0 ||
			(!duplex && direction == "both" && flows%4 != 0) {
			return errors.New("mixed transport requires equal transport and direction counts")
		}
		r.Transport = "tcp"
	}
	if duplex {
		r.BytesPerSecond /= 2
	}
	r.TargetHost, r.ExpectedSource = target, source
	r.InitialHello = transport == "tcp"
	if probeMode {
		if direction != "both" || flows != 1 || transport != "tcp" || seconds != (probeRounds+19)/20 {
			return errors.New("probe requires a bounded bidirectional handshake check")
		}
		r.Probe, r.ProbeRounds, r.BytesPerSecond = true, probeRounds, 640
	}
	if source != "" && net.ParseIP(source) == nil {
		return errors.New("route witness requires a literal expected origin peer")
	}
	if err := validate(r); err != nil {
		return err
	}
	var ready sync.WaitGroup
	ready.Add(flows)
	start := make(chan struct{})
	results := make(chan []flowResult, flows)
	for i := 0; i < flows; i++ {
		current := r
		current.Transport, current.Direction = flowKindDirection(transport, direction, i, flows, duplex)
		if current.Transport == "udp" {
			current.UDPDestinations = udpDestinations
		}
		current.InitialHello = current.Transport == "tcp"
		current.Seed += uint64(i)
		// Serialize only multi-port hello setup; all flows still await start.
		prepareSequentially := current.Transport == "udp" && current.UDPDestinations > 1
		flowReady := &ready
		if prepareSequentially {
			flowReady = new(sync.WaitGroup)
			flowReady.Add(1)
		}
		go func() { results <- clientFlow(peer, current, flowReady, start) }()
		if prepareSequentially {
			flowReady.Wait()
			ready.Done()
		}
	}
	ready.Wait()
	if err := startBarrier(readyFile, startFile, flows); err != nil {
		return err
	}
	began := time.Now()
	close(start)
	rows := make([]flowResult, 0, flows)
	var received, sent int64
	success := true
	for i := 0; i < flows; i++ {
		for _, row := range <-results {
			rows = append(rows, row)
			received += row.Received.Bytes
			sent += row.Sent.Bytes
			if row.Error != "" {
				success = false
			}
		}
	}
	elapsed := time.Since(began).Seconds()
	window := elapsed
	if window < float64(seconds) {
		window = float64(seconds)
	}
	goodput := float64(received) * 8 / window
	report := map[string]any{"complete": success, "transport": transport, "direction": direction, "flows": rows,
		"data_connection_count":     flows,
		"single_connection_duplex":  duplex && flows == 1,
		"external_start_barrier":    readyFile != "" && startFile != "",
		"udp_pacing_credit_records": udpPacingCredit,
		"udp_destinations":          udpDestinations,
		"sent_bytes":                sent, "received_bytes": received, "elapsed_seconds": elapsed, "offered_bps": int64(mbps) * 1000000,
		"receiver_goodput_bps": goodput, "nominal_seconds": seconds, "payload_bytes": frameSize(r),
		"rate_pass": success && goodput >= float64(mbps)*1000000*0.99}
	report["entrypoint"] = "linux-real-tun"
	if transport == "mixed" {
		report["payload_bytes_by_transport"] = map[string]int{"tcp": 65536, "udp": 1200}
	}
	if probeMode {
		report["probe"] = true
		report["probe_rounds"] = probeRounds
		report["offered_bps"] = 0
		report["rate_pass"] = false
	}
	if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
		return errors.New("client report output failed")
	}
	if !success {
		return errors.New("payload validation failed")
	}
	return nil
}

func main() {
	mode := flag.String("mode", "client", "origin/client/dns")
	peer := flag.String("peer", "", "isolated origin control address")
	transport := flag.String("transport", "tcp", "tcp/udp/mixed")
	direction := flag.String("direction", "up", "up/down/both")
	seconds := flag.Int("seconds", 10, "bounded measurement duration")
	flows := flag.Int("flows", 16, "bounded flow count")
	mbps := flag.Int("mbps", 1000, "aggregate offered application Mbps")
	target := flag.String("target", "", "controlled destination name resolved through the TUN")
	source := flag.String("expect-source", "", "origin must observe this literal peer IP")
	readyFile := flag.String("ready-file", "", "owned driver readiness file for paired load")
	startFile := flag.String("start-file", "", "owned common release file for paired load")
	dnsQPS := flag.Int("dns-qps", 1000, "bounded independently paced DNS queries per second")
	dnsServer := flag.String("dns-server", "198.18.0.1:53", "literal controlled TUN DNS endpoint")
	dnsAnswer := flag.String("dns-answer", "", "literal expected controlled DNS answer")
	dnsSuffix := flag.String("dns-suffix", "load.test", "controlled unique-name DNS suffix")
	flag.IntVar(&udpDestinations, "udp-destinations", 1, "ports per unchanged UDP source socket (1-256, fixture bound)")
	flag.BoolVar(&probeMode, "probe", false, "bounded duplex setup probe; never bandwidth evidence")
	flag.IntVar(&probeRounds, "probe-rounds", 1, "1-100 duplex exchanges without reconnecting")
	flag.Parse()
	var err error
	if *mode == "origin" {
		err = origin()
	} else if *mode == "client" {
		err = runClient(*peer, *transport, *direction, *seconds, *flows, *mbps, *target, *source, *readyFile, *startFile)
	} else if *mode == "dns" {
		err = runDNSPressure(*dnsServer, *dnsAnswer, *dnsSuffix, *readyFile, *startFile, *seconds, *dnsQPS)
	} else {
		err = fmt.Errorf("invalid mode")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
