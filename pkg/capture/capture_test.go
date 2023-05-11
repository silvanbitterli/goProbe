package capture

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/els0r/goProbe/pkg/capture/capturetypes"
	"github.com/fako1024/slimcap/capture"
	"github.com/fako1024/slimcap/capture/afpacket/afring"
	"github.com/fako1024/slimcap/link"
	"github.com/stretchr/testify/require"
)

func testDeadlock(t *testing.T, maxPkts int) {

	mockSrc, err := afring.NewMockSource("mock",
		afring.CaptureLength(link.CaptureLengthMinimalIPv4Transport),
	)
	require.Nil(t, err)
	mockC := newMockCapture(mockSrc)

	testPacket, err := genDummyPacket()
	require.Nil(t, err)

	var errChan chan error
	if maxPkts >= 0 {
		go func() {
			errChan = mockSrc.Run()
			for i := 0; i < maxPkts; i++ {
				mockSrc.AddPacket(testPacket)
			}
			mockSrc.Done()
			mockSrc.ForceBlockRelease()
		}()
	} else {
		for mockSrc.CanAddPackets() {
			mockSrc.AddPacket(testPacket)
		}
		errChan = mockSrc.RunNoDrain(time.Microsecond)
	}

	start := time.Now()
	time.AfterFunc(100*time.Millisecond, func() {
		for i := 0; i < 20; i++ {
			mockC.rotate()
			time.Sleep(10 * time.Millisecond)
		}

		require.Nil(t, mockSrc.Close())
	})

	mockC.process()

	select {
	case <-errChan:
		break
	case <-time.After(10 * time.Second):
		t.Fatalf("potential deadlock situation on rotation logic")
	}

	if time.Since(start) > 2*time.Second {
		t.Fatalf("potential deadlock situation on rotation logic")
	}

	require.Nil(t, mockSrc.Free())
}

func newMockCapture(src capture.SourceZeroCopy) *Capture {
	return &Capture{
		iface:         src.Link().Name,
		mutex:         sync.Mutex{},
		stateMutex:    sync.RWMutex{},
		cmdChan:       make(chan captureCommand),
		captureErrors: make(chan error),
		lastRotationStats: capturetypes.PacketStats{
			CaptureStats: &capturetypes.CaptureStats{},
		},
		rotationState: newRotationState(),
		closeState:    make(chan struct{}, 1),
		flowLog:       capturetypes.NewFlowLog(),
		errMap:        make(map[string]int),
		ctx:           context.Background(),
		captureHandle: src,
	}
}

func genDummyPacket() (capture.Packet, error) {
	return capture.BuildPacket(
		net.ParseIP("1.2.3.4"),
		net.ParseIP("4.5.6.7"),
		1,
		2,
		6, []byte{1, 2}, capture.PacketOutgoing, 128)
}
