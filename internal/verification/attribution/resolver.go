package attribution

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"path"
	"sort"
	"strconv"
	"strings"
)

type procFS interface {
	ReadFile(name string) ([]byte, error)
	ReadDir(name string) ([]fs.DirEntry, error)
	Readlink(name string) (string, error)
}

type Resolver struct {
	procRoot string
	procFS   procFS
}

func NewResolver(procRoot string, procFS procFS) Resolver {
	if procRoot == "" {
		procRoot = "/proc"
	}
	return Resolver{
		procRoot: procRoot,
		procFS:   procFS,
	}
}

func (r Resolver) ResolveLocalSourceOwner(flow Flow) (Result, error) {
	sockets, err := r.loadSockets()
	if err != nil {
		return Result{}, err
	}

	inodes := make([]string, 0, 1)
	for _, socket := range sockets {
		if socket.localIP == flow.SrcIP && socket.localPort == flow.SrcPort &&
			socket.remoteIP == flow.DstIP && socket.remotePort == flow.DstPort {
			inodes = append(inodes, socket.inode)
		}
	}

	switch len(inodes) {
	case 0:
		return Result{
			Status: Unattributed,
			Detail: "flow was not present in proc socket tables",
		}, nil
	case 1:
	default:
		return Result{
			Status: Ambiguous,
			Detail: fmt.Sprintf("multiple socket inodes matched flow: %s", strings.Join(inodes, ",")),
		}, nil
	}

	owners, err := r.findOwners(inodes[0])
	if err != nil {
		return Result{}, err
	}
	switch len(owners) {
	case 0:
		return Result{
			Status: Unattributed,
			Detail: fmt.Sprintf("socket inode %s no longer belongs to a live process", inodes[0]),
		}, nil
	case 1:
		return Result{
			Status: Attributed,
			Workload: &Workload{
				PID:                   owners[0].pid,
				Executable:            owners[0].executable,
				ProcessStartTimeTicks: owners[0].processStartTimeTicks,
				SocketInode:           owners[0].socketInode,
			},
			Detail: fmt.Sprintf("resolved inode %s to pid %d", inodes[0], owners[0].pid),
		}, nil
	default:
		details := make([]string, 0, len(owners))
		for _, owner := range owners {
			details = append(details, fmt.Sprintf("%d:%s", owner.pid, owner.executable))
		}
		return Result{
			Status: Ambiguous,
			Detail: fmt.Sprintf("multiple processes reference socket inode %s: %s", inodes[0], strings.Join(details, ",")),
		}, nil
	}
}

type procSocket struct {
	inode      string
	localIP    string
	localPort  uint16
	remoteIP   string
	remotePort uint16
}

type socketOwner struct {
	pid                   int
	executable            string
	processStartTimeTicks uint64
	socketInode           string
}

func (r Resolver) loadSockets() ([]procSocket, error) {
	paths := []string{
		path.Join(r.procRoot, "net", "tcp"),
		path.Join(r.procRoot, "net", "tcp6"),
	}

	var sockets []procSocket
	for _, filePath := range paths {
		payload, err := r.procFS.ReadFile(filePath)
		if err != nil {
			if isNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("read %s: %w", filePath, err)
		}
		parsed, err := parseSocketTable(payload)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", filePath, err)
		}
		sockets = append(sockets, parsed...)
	}
	return sockets, nil
}

func (r Resolver) findOwners(inode string) ([]socketOwner, error) {
	entries, err := r.procFS.ReadDir(r.procRoot)
	if err != nil {
		return nil, fmt.Errorf("read proc root: %w", err)
	}

	var owners []socketOwner
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		fdDir := path.Join(r.procRoot, entry.Name(), "fd")
		fdEntries, err := r.procFS.ReadDir(fdDir)
		if err != nil {
			if isNotExist(err) || isPermission(err) {
				continue
			}
			return nil, fmt.Errorf("read %s: %w", fdDir, err)
		}

		ownsSocket := false
		for _, fdEntry := range fdEntries {
			target, err := r.procFS.Readlink(path.Join(fdDir, fdEntry.Name()))
			if err != nil {
				if isNotExist(err) || isPermission(err) {
					continue
				}
				return nil, fmt.Errorf("readlink %s: %w", path.Join(fdDir, fdEntry.Name()), err)
			}
			if target == fmt.Sprintf("socket:[%s]", inode) {
				ownsSocket = true
				break
			}
		}
		if !ownsSocket {
			continue
		}

		exeTarget, err := r.procFS.Readlink(path.Join(r.procRoot, entry.Name(), "exe"))
		if err != nil {
			if isNotExist(err) || isPermission(err) {
				continue
			} else {
				return nil, fmt.Errorf("readlink exe for pid %d: %w", pid, err)
			}
		}

		startTimeTicks, err := r.readProcessStartTimeTicks(pid)
		if err != nil {
			if isNotExist(err) || isPermission(err) {
				continue
			}
			return nil, fmt.Errorf("read proc stat for pid %d: %w", pid, err)
		}

		owners = append(owners, socketOwner{
			pid:                   pid,
			executable:            executableName(exeTarget),
			processStartTimeTicks: startTimeTicks,
			socketInode:           inode,
		})
	}

	sort.Slice(owners, func(i, j int) bool {
		return owners[i].pid < owners[j].pid
	})
	return owners, nil
}

func (r Resolver) readProcessStartTimeTicks(pid int) (uint64, error) {
	payload, err := r.procFS.ReadFile(path.Join(r.procRoot, strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, err
	}

	text := strings.TrimSpace(string(payload))
	closing := strings.LastIndex(text, ")")
	if closing == -1 || closing+1 >= len(text) {
		return 0, fmt.Errorf("unexpected proc stat format")
	}

	fields := strings.Fields(text[closing+1:])
	if len(fields) <= 19 {
		return 0, fmt.Errorf("unexpected proc stat field count")
	}

	startTimeTicks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse proc stat start time %q: %w", fields[19], err)
	}
	return startTimeTicks, nil
}

func parseSocketTable(payload []byte) ([]procSocket, error) {
	scanner := bufio.NewScanner(bytes.NewReader(payload))
	firstLine := true
	var sockets []procSocket
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if firstLine {
			firstLine = false
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 10 {
			return nil, fmt.Errorf("unexpected socket table format")
		}

		localIP, localPort, err := decodeProcAddress(fields[1])
		if err != nil {
			return nil, err
		}
		remoteIP, remotePort, err := decodeProcAddress(fields[2])
		if err != nil {
			return nil, err
		}

		sockets = append(sockets, procSocket{
			inode:      fields[9],
			localIP:    localIP,
			localPort:  localPort,
			remoteIP:   remoteIP,
			remotePort: remotePort,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return sockets, nil
}

func decodeProcAddress(value string) (string, uint16, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("unexpected proc address %q", value)
	}

	portValue, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return "", 0, fmt.Errorf("parse port %q: %w", parts[1], err)
	}

	rawAddress := parts[0]
	switch len(rawAddress) {
	case 8:
		return decodeIPv4(rawAddress), uint16(portValue), nil
	case 32:
		return decodeIPv6(rawAddress), uint16(portValue), nil
	default:
		return "", 0, fmt.Errorf("unexpected proc address width %q", rawAddress)
	}
}

func decodeIPv4(value string) string {
	buf := make([]byte, 4)
	for i := 0; i < 4; i++ {
		decoded, _ := strconv.ParseUint(value[i*2:i*2+2], 16, 8)
		buf[3-i] = byte(decoded)
	}
	return net.IP(buf).String()
}

func decodeIPv6(value string) string {
	buf := make([]byte, 16)
	for block := 0; block < 4; block++ {
		chunk := value[block*8 : block*8+8]
		for i := 0; i < 4; i++ {
			decoded, _ := strconv.ParseUint(chunk[i*2:i*2+2], 16, 8)
			buf[block*4+(3-i)] = byte(decoded)
		}
	}
	return net.IP(buf).String()
}

func isNotExist(err error) bool {
	return errors.Is(err, fs.ErrNotExist)
}

func isPermission(err error) bool {
	return errors.Is(err, fs.ErrPermission)
}
