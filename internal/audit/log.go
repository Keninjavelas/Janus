package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Event struct {
	Type      string         `json:"type"`
	Timestamp time.Time      `json:"timestamp"`
	Payload   map[string]any `json:"payload,omitempty"`
}

type Record struct {
	Index        int             `json:"index"`
	Type         string          `json:"type"`
	Timestamp    time.Time       `json:"timestamp"`
	Payload      json.RawMessage `json:"payload,omitempty"`
	PreviousHash string          `json:"previous_hash,omitempty"`
	Hash         string          `json:"hash"`
}

type VerifyResult struct {
	Valid         bool   `json:"valid"`
	Records       int    `json:"records"`
	FailureReason string `json:"failure_reason,omitempty"`
}

type Log struct {
	path string
	mu   sync.Mutex
}

func NewLog(path string) *Log {
	return &Log{path: path}
}

func (l *Log) Append(event Event) (Record, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	records, err := l.readAllLocked()
	if err != nil {
		return Record{}, err
	}

	payload, err := json.Marshal(event.Payload)
	if err != nil {
		return Record{}, err
	}

	record := Record{
		Index:     len(records),
		Type:      event.Type,
		Timestamp: event.Timestamp.UTC(),
		Payload:   json.RawMessage(payload),
	}
	if len(records) > 0 {
		record.PreviousHash = records[len(records)-1].Hash
	}

	record.Hash, err = hashRecord(record)
	if err != nil {
		return Record{}, err
	}

	if err := os.MkdirAll(filepath.Dir(l.path), 0o755); err != nil {
		return Record{}, err
	}
	file, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return Record{}, err
	}
	defer file.Close()

	if err := json.NewEncoder(file).Encode(record); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (l *Log) ReadAll() ([]Record, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.readAllLocked()
}

func (l *Log) Verify() (VerifyResult, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	records, err := l.readAllLocked()
	if err != nil {
		return VerifyResult{}, err
	}
	var previous string
	for i, record := range records {
		if record.Index != i {
			return VerifyResult{Valid: false, Records: len(records), FailureReason: "record index mismatch"}, nil
		}
		if record.PreviousHash != previous {
			return VerifyResult{Valid: false, Records: len(records), FailureReason: "previous hash mismatch"}, nil
		}
		expected, err := hashRecord(Record{
			Index:        record.Index,
			Type:         record.Type,
			Timestamp:    record.Timestamp,
			Payload:      record.Payload,
			PreviousHash: record.PreviousHash,
		})
		if err != nil {
			return VerifyResult{}, err
		}
		if record.Hash != expected {
			return VerifyResult{Valid: false, Records: len(records), FailureReason: "record hash mismatch"}, nil
		}
		previous = record.Hash
	}
	return VerifyResult{Valid: true, Records: len(records)}, nil
}

func (l *Log) readAllLocked() ([]Record, error) {
	file, err := os.Open(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()

	records := make([]Record, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var record Record
		if err := json.Unmarshal(line, &record); err != nil {
			return nil, fmt.Errorf("decode audit record: %w", err)
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

func hashRecord(record Record) (string, error) {
	type envelope struct {
		Index        int             `json:"index"`
		Type         string          `json:"type"`
		Timestamp    time.Time       `json:"timestamp"`
		Payload      json.RawMessage `json:"payload,omitempty"`
		PreviousHash string          `json:"previous_hash,omitempty"`
	}
	payload, err := json.Marshal(envelope{
		Index:        record.Index,
		Type:         record.Type,
		Timestamp:    record.Timestamp.UTC(),
		Payload:      record.Payload,
		PreviousHash: record.PreviousHash,
	})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}
