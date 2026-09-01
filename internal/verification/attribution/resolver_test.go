package attribution

import (
	"fmt"
	"io/fs"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestResolveLocalSourceOwnerAttributed(t *testing.T) {
	resolver := NewResolver("/proc", fakeProcFS{
		files: map[string]string{
			"/proc/net/tcp": procTCPTable(
				procTCPRow("127.0.0.1", 52314, "127.0.0.1", 8443, "12345"),
			),
			"/proc/4217/stat": procStatRow(4217, "janus-test-client", 987654),
		},
		entries: map[string][]string{
			"/proc":         {"4217"},
			"/proc/4217/fd": {"5"},
		},
		links: map[string]string{
			"/proc/4217/fd/5": "socket:[12345]",
			"/proc/4217/exe":  "/usr/bin/janus-test-client",
		},
	})

	result, err := resolver.ResolveLocalSourceOwner(Flow{
		SrcIP: "127.0.0.1", SrcPort: 52314,
		DstIP: "127.0.0.1", DstPort: 8443,
	})
	if err != nil {
		t.Fatalf("resolve owner: %v", err)
	}
	if result.Status != Attributed {
		t.Fatalf("expected ATTRIBUTED, got %s (%s)", result.Status, result.Detail)
	}
	if result.Workload == nil {
		t.Fatal("expected workload metadata")
	}
	if result.Workload.PID != 4217 || result.Workload.Executable != "janus-test-client" {
		t.Fatalf("unexpected workload: %#v", result.Workload)
	}
	if result.Workload.ProcessStartTimeTicks != 987654 {
		t.Fatalf("expected process start ticks 987654, got %d", result.Workload.ProcessStartTimeTicks)
	}
	if result.Workload.SocketInode != "12345" {
		t.Fatalf("expected socket inode 12345, got %q", result.Workload.SocketInode)
	}
}

func TestResolveLocalSourceOwnerSimultaneousConnections(t *testing.T) {
	resolver := NewResolver("/proc", fakeProcFS{
		files: map[string]string{
			"/proc/net/tcp": procTCPTable(
				procTCPRow("127.0.0.1", 52314, "127.0.0.1", 8443, "12345"),
				procTCPRow("127.0.0.1", 52315, "127.0.0.1", 8443, "67890"),
			),
			"/proc/4217/stat": procStatRow(4217, "janus-test-client-a", 111111),
			"/proc/5319/stat": procStatRow(5319, "janus-test-client-b", 222222),
		},
		entries: map[string][]string{
			"/proc":         {"4217", "5319"},
			"/proc/4217/fd": {"5"},
			"/proc/5319/fd": {"7"},
		},
		links: map[string]string{
			"/proc/4217/fd/5": "socket:[12345]",
			"/proc/4217/exe":  "/usr/bin/janus-test-client-a",
			"/proc/5319/fd/7": "socket:[67890]",
			"/proc/5319/exe":  "/usr/bin/janus-test-client-b",
		},
	})

	first, err := resolver.ResolveLocalSourceOwner(Flow{
		SrcIP: "127.0.0.1", SrcPort: 52314,
		DstIP: "127.0.0.1", DstPort: 8443,
	})
	if err != nil {
		t.Fatalf("resolve first owner: %v", err)
	}
	second, err := resolver.ResolveLocalSourceOwner(Flow{
		SrcIP: "127.0.0.1", SrcPort: 52315,
		DstIP: "127.0.0.1", DstPort: 8443,
	})
	if err != nil {
		t.Fatalf("resolve second owner: %v", err)
	}

	if first.Workload == nil || first.Workload.PID != 4217 {
		t.Fatalf("unexpected first workload: %#v", first.Workload)
	}
	if second.Workload == nil || second.Workload.PID != 5319 {
		t.Fatalf("unexpected second workload: %#v", second.Workload)
	}
	if first.Workload.SocketInode != "12345" || second.Workload.SocketInode != "67890" {
		t.Fatalf("unexpected socket inode mapping: first=%#v second=%#v", first.Workload, second.Workload)
	}
}

func TestResolveLocalSourceOwnerVanishedSocket(t *testing.T) {
	resolver := NewResolver("/proc", fakeProcFS{
		files: map[string]string{
			"/proc/net/tcp": procTCPTable(
				procTCPRow("127.0.0.1", 52314, "127.0.0.1", 8443, "12345"),
			),
			"/proc/4217/stat": procStatRow(4217, "janus-test-client-a", 111111),
			"/proc/5319/stat": procStatRow(5319, "janus-test-client-b", 222222),
		},
		entries: map[string][]string{
			"/proc": {"4217"},
		},
	})

	result, err := resolver.ResolveLocalSourceOwner(Flow{
		SrcIP: "127.0.0.1", SrcPort: 52314,
		DstIP: "127.0.0.1", DstPort: 8443,
	})
	if err != nil {
		t.Fatalf("resolve vanished owner: %v", err)
	}
	if result.Status != Unattributed {
		t.Fatalf("expected UNATTRIBUTED, got %s (%s)", result.Status, result.Detail)
	}
}

func TestResolveLocalSourceOwnerAmbiguous(t *testing.T) {
	resolver := NewResolver("/proc", fakeProcFS{
		files: map[string]string{
			"/proc/net/tcp": procTCPTable(
				procTCPRow("127.0.0.1", 52314, "127.0.0.1", 8443, "12345"),
			),
			"/proc/4217/stat": procStatRow(4217, "janus-test-client-a", 111111),
			"/proc/5319/stat": procStatRow(5319, "janus-test-client-b", 222222),
		},
		entries: map[string][]string{
			"/proc":         {"4217", "5319"},
			"/proc/4217/fd": {"5"},
			"/proc/5319/fd": {"7"},
		},
		links: map[string]string{
			"/proc/4217/fd/5": "socket:[12345]",
			"/proc/4217/exe":  "/usr/bin/janus-test-client-a",
			"/proc/5319/fd/7": "socket:[12345]",
			"/proc/5319/exe":  "/usr/bin/janus-test-client-b",
		},
	})

	result, err := resolver.ResolveLocalSourceOwner(Flow{
		SrcIP: "127.0.0.1", SrcPort: 52314,
		DstIP: "127.0.0.1", DstPort: 8443,
	})
	if err != nil {
		t.Fatalf("resolve ambiguous owner: %v", err)
	}
	if result.Status != Ambiguous {
		t.Fatalf("expected AMBIGUOUS, got %s (%s)", result.Status, result.Detail)
	}
}

type fakeProcFS struct {
	files   map[string]string
	entries map[string][]string
	links   map[string]string
}

func (f fakeProcFS) ReadFile(name string) ([]byte, error) {
	content, ok := f.files[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return []byte(content), nil
}

func (f fakeProcFS) ReadDir(name string) ([]fs.DirEntry, error) {
	names, ok := f.entries[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return newNamedEntries(names), nil
}

func (f fakeProcFS) Readlink(name string) (string, error) {
	target, ok := f.links[name]
	if !ok {
		return "", fs.ErrNotExist
	}
	return target, nil
}

type namedEntry struct {
	name string
	dir  bool
}

func newNamedEntries(names []string) []fs.DirEntry {
	entries := make([]fs.DirEntry, 0, len(names))
	for _, name := range names {
		entries = append(entries, namedEntry{
			name: name,
			dir:  !strings.Contains(name, "."),
		})
	}
	return entries
}

func (e namedEntry) Name() string { return e.name }
func (e namedEntry) IsDir() bool  { return e.dir }
func (e namedEntry) Type() fs.FileMode {
	if e.dir {
		return fs.ModeDir
	}
	return 0
}
func (e namedEntry) Info() (fs.FileInfo, error) { return namedInfo{name: e.name, dir: e.dir}, nil }

type namedInfo struct {
	name string
	dir  bool
}

func (i namedInfo) Name() string { return i.name }
func (i namedInfo) Size() int64  { return 0 }
func (i namedInfo) Mode() fs.FileMode {
	if i.dir {
		return fs.ModeDir | 0o555
	}
	return 0o444
}
func (i namedInfo) ModTime() time.Time { return time.Time{} }
func (i namedInfo) IsDir() bool        { return i.dir }
func (i namedInfo) Sys() any           { return nil }

func procTCPTable(rows ...string) string {
	return "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" + strings.Join(rows, "\n") + "\n"
}

func procTCPRow(localIP string, localPort uint16, remoteIP string, remotePort uint16, inode string) string {
	return fmt.Sprintf(
		"   0: %s:%04X %s:%04X 01 00000000:00000000 00:00000000 00000000  1000        0 %s 1 0000000000000000 100 0 0 10 0",
		encodeIPv4(localIP),
		localPort,
		encodeIPv4(remoteIP),
		remotePort,
		inode,
	)
}

func encodeIPv4(ip string) string {
	parsed := netParseIPv4(ip)
	return fmt.Sprintf("%02X%02X%02X%02X", parsed[3], parsed[2], parsed[1], parsed[0])
}

func netParseIPv4(ip string) [4]byte {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		panic("invalid ipv4 test input")
	}
	var out [4]byte
	for i, part := range parts {
		value, err := strconv.Atoi(part)
		if err != nil {
			panic(err)
		}
		out[i] = byte(value)
	}
	return out
}

func procStatRow(pid int, comm string, startTimeTicks uint64) string {
	fields := []string{
		"S",
		"1",
		"1",
		"1",
		"1",
		"1",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"0",
		"20",
		"0",
		"1",
		"0",
		strconv.FormatUint(startTimeTicks, 10),
	}
	fields = append(fields,
		"0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
		"0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
		"0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
		"0", "0",
	)
	return fmt.Sprintf("%d (%s) %s", pid, comm, strings.Join(fields, " "))
}
