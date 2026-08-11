package wire

type StreamObserver struct {
	buffer []byte
}

func (o *StreamObserver) Feed(chunk []byte) (*Observation, error) {
	o.buffer = append(o.buffer, chunk...)
	observation, err := ObserveServerHello(o.buffer)
	if err == nil {
		return &observation, nil
	}
	if err == ErrIncompleteRecord || err == ErrIncompleteHandshake {
		return nil, nil
	}
	return nil, err
}
