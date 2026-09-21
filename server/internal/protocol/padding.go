package protocol

import (
	"log/slog"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// PaddingGenerator sends random PADDING frames at random intervals
// to make traffic patterns look like normal web browsing.
type PaddingGenerator struct {
	conn     *websocket.Conn
	mu       sync.Mutex
	minDelay int // seconds
	maxDelay int // seconds
	running  atomic.Bool
	stopCh   chan struct{}
	wg       sync.WaitGroup
	logger   *slog.Logger
}

// NewPaddingGenerator creates a new padding generator.
func NewPaddingGenerator(conn *websocket.Conn, minDelay, maxDelay int, logger *slog.Logger) *PaddingGenerator {
	return &PaddingGenerator{
		conn:     conn,
		minDelay: minDelay,
		maxDelay: maxDelay,
		stopCh:   make(chan struct{}),
		logger:   logger,
	}
}

// Start begins sending padding frames in a goroutine.
func (pg *PaddingGenerator) Start() {
	if pg.running.Swap(true) {
		return // already running
	}
	pg.wg.Add(1)
	go pg.run()
}

// Stop halts the padding generator.
func (pg *PaddingGenerator) Stop() {
	if !pg.running.Swap(false) {
		return
	}
	close(pg.stopCh)
	pg.wg.Wait()
}

// UpdateConn updates the WebSocket connection (used during session migration).
func (pg *PaddingGenerator) UpdateConn(conn *websocket.Conn) {
	pg.mu.Lock()
	defer pg.mu.Unlock()
	pg.conn = conn
}

func (pg *PaddingGenerator) run() {
	defer pg.wg.Done()

	for {
		// Random delay between min and max seconds
		delay := pg.minDelay + rand.Intn(pg.maxDelay-pg.minDelay+1)
		timer := time.NewTimer(time.Duration(delay) * time.Second)

		select {
		case <-pg.stopCh:
			timer.Stop()
			return
		case <-timer.C:
		}

		// Generate random padding frame with random size (32-512 bytes)
		padSize := 32 + rand.Intn(481)
		frame := NewPaddingFrame(padSize)
		// Randomly add padding flag to make it even more random
		if rand.Intn(2) == 0 {
			frame.Flags |= FlagHasPadding
		}

		pg.mu.Lock()
		conn := pg.conn
		pg.mu.Unlock()

		if conn == nil {
			continue
		}

		data := frame.Encode()
		if err := conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
			pg.logger.Debug("padding write failed", "error", err)
			// Don't stop on error — connection might recover
			continue
		}
	}
}

// RandomPadding generates random bytes for padding.
func RandomPadding(min, max int) []byte {
	size := min + rand.Intn(max-min+1)
	buf := make([]byte, size)
	rand.Read(buf)
	return buf
}
