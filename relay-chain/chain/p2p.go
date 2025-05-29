package chain

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

type Node struct {
	Host         host.Host
	peers        map[peer.ID]*peer.AddrInfo
	peersLock    sync.RWMutex
	chain        *Blockchain
	badPeers     map[peer.ID]int
	badPeersLock sync.RWMutex
}

func GetLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return ipnet.IP.String()
		}
	}
	return "127.0.0.1"
}

func NewNode(ctx context.Context, port int) (*Node, error) {
	ip := GetLocalIP()
	// ip := "192.168.45.152"
	listenAddr := fmt.Sprintf("/ip4/%s/tcp/%d", ip, port)

	h, err := libp2p.New(
		libp2p.ListenAddrStrings(listenAddr),
	)
	if err != nil {
		return nil, err
	}

	node := &Node{
		Host:     h,
		peers:    make(map[peer.ID]*peer.AddrInfo),
		badPeers: make(map[peer.ID]int),
	}

	h.SetStreamHandler("/blackhole/1.0.0", node.handleStream)

	fmt.Println("🆔 Peer ID:", h.ID().String())
	for _, addr := range h.Addrs() {
		fullAddr := fmt.Sprintf("%s/p2p/%s", addr.String(), h.ID().String())
		fmt.Println("🚀 Your peer multiaddr:")
		fmt.Println("   " + fullAddr)
		break
	}

	return node, nil
}

func (n *Node) Connect(ctx context.Context, addr string) error {
	maddr, err := multiaddr.NewMultiaddr(addr)
	if err != nil {
		return err
	}

	info, err := peer.AddrInfoFromP2pAddr(maddr)
	if err != nil {
		return err
	}

	fmt.Println("🌐 Connecting to:", addr)
	if err := n.Host.Connect(ctx, *info); err != nil {
		return err
	}

	n.peersLock.Lock()
	n.peers[info.ID] = info
	n.peersLock.Unlock()
	return nil
}

func (n *Node) SetChain(bc *Blockchain) {
	n.chain = bc
}

func (n *Node) disconnectPeer(peerID peer.ID) {
	n.peersLock.Lock()
	delete(n.peers, peerID)
	n.peersLock.Unlock()
	n.Host.Network().ClosePeer(peerID)
	fmt.Printf("🚫 Disconnected peer %s due to invalid blocks\n", peerID)
}

type BlockchainComparisonResult struct {
	IsSameLength    bool
	LocalAhead      bool
	PeerAhead       bool
	CommonPrefix    int
	DivergencePoint int
	Conflict        bool
	Notes           []string
}

func (bc *Blockchain) CompareWithPeer(peer *Blockchain) BlockchainComparisonResult {
	bc.mu.RLock()
	peer.mu.RLock()
	defer bc.mu.RUnlock()
	defer peer.mu.RUnlock()

	result := BlockchainComparisonResult{}

	localLen := len(bc.Blocks)
	peerLen := len(peer.Blocks)

	result.IsSameLength = localLen == peerLen
	result.LocalAhead = localLen > peerLen
	result.PeerAhead = peerLen > localLen

	minLen := localLen
	if peerLen < minLen {
		minLen = peerLen
	}

	diverged := false
	for i := 0; i < minLen; i++ {
		if bc.Blocks[i].Hash != peer.Blocks[i].Hash {
			result.DivergencePoint = i
			result.CommonPrefix = i
			result.Conflict = true
			result.Notes = append(result.Notes, fmt.Sprintf("⚠️ Fork at block %d: local=%s, peer=%s", i, bc.Blocks[i].Hash[:8], peer.Blocks[i].Hash[:8]))
			diverged = true
			break
		}
	}

	if !diverged {
		result.CommonPrefix = minLen
		result.DivergencePoint = -1
		result.Conflict = false
		result.Notes = append(result.Notes, "✅ Chains are consistent up to current block.")
	}

	if result.PeerAhead {
		result.Notes = append(result.Notes, fmt.Sprintf("📥 Peer is ahead by %d blocks.", peerLen-localLen))
	} else if result.LocalAhead {
		result.Notes = append(result.Notes, fmt.Sprintf("📤 We are ahead by %d blocks.", localLen-peerLen))
	}

	if bc.Blocks[0].Hash != peer.Blocks[0].Hash {
		result.Notes = append(result.Notes, "🚨 Genesis block mismatch! Completely different chains.")
	}

	return result
}

func (n *Node) handleStream(s network.Stream) {
	defer s.Close()

	peerID := s.Conn().RemotePeer()
	fmt.Printf("📡 Received stream from peer: %s\n", peerID)

	var msg Message
	s.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer s.SetReadDeadline(time.Time{}) // reset deadline after
	if err := msg.Decode(s); err != nil {
		fmt.Printf("❌ Error decoding message from peer %s: %v\n", peerID, err)
		if msg.Version != ProtocolVersion {
			fmt.Println("actual version: ", ProtocolVersion)
			fmt.Printf("⚠️ Version mismatch from peer %s: got %d, expected %d\n", peerID, msg.Version, ProtocolVersion)
			n.disconnectPeer(peerID)
		}
		return
	}

	switch msg.Type {
	case MessageTypeTx:
		tx, err := DeserializeTransaction(msg.Data)
		if err != nil {
			fmt.Printf("❌ Error deserializing transaction from peer %s: %v\n", peerID, err)
			return
		}
		fmt.Println("hello inside msgtypetx")
		// if tx.Verify() {
		fmt.Println("hello inside tx.verify")
		n.chain.mu.Lock()
		n.chain.PendingTxs = append(n.chain.PendingTxs, tx)
		n.chain.mu.Unlock()
		fmt.Printf("📥 Added transaction %s from peer %s to pending\n", tx.ID, peerID)
		// }
		fmt.Println(msg.Type)
	case MessageTypeBlock:
		block, err := DeserializeBlock(msg.Data)
		if err != nil {
			if strings.Contains(err.Error(), "CommonType") {
				fmt.Printf("⚠️ Skipping block with CommonType reference from peer %s\n", peerID)
				n.disconnectPeer(peerID)
				return
			}
			fmt.Printf("❌ Error deserializing block from peer %s: %v\n", peerID, err)
			n.badPeersLock.Lock()
			n.badPeers[peerID]++
			if n.badPeers[peerID] >= 3 {
				n.disconnectPeer(peerID)
			}
			n.badPeersLock.Unlock()
			return
		}
		fmt.Printf("📑 Block details: Index=%d, Hash=%s, PrevHash=%s, Validator=%s, TxCount=%d\n",
			block.Header.Index, block.Hash, block.Header.PreviousHash, block.Header.Validator, len(block.Transactions))
		if n.chain.AddBlock(block) {
			fmt.Printf("🧱 Added block %d from peer %s\n", block.Header.Index, peerID)
			n.badPeersLock.Lock()
			n.badPeers[peerID] = 0
			n.badPeersLock.Unlock()
		} else {
			fmt.Printf("⚠️ Failed to add block %d from peer %s\n", block.Header.Index, peerID)
		}
	case MessageTypeSyncReq:
		startIndex := uint64(0)
		endIndex := uint64(0)
		if len(msg.Data) >= 16 {
			startIndex = binary.BigEndian.Uint64(msg.Data[:8])
			endIndex = binary.BigEndian.Uint64(msg.Data[8:])
		} else {
			n.chain.mu.RLock()
			startIndex = 0
			if len(n.chain.Blocks) > 0 {
				endIndex = n.chain.Blocks[len(n.chain.Blocks)-1].Header.Index
			}
			n.chain.mu.RUnlock()
		}
		n.chain.mu.RLock()
		blocks := make([]*Block, 0)
		for _, block := range n.chain.Blocks {
			if block.Header.Index < startIndex || block.Header.Index > endIndex {
				continue
			}
			blocks = append(blocks, block)
		}
		n.chain.mu.RUnlock()
		for _, block := range blocks {
			data := block.Serialize()
			resp := &Message{
				Type:    MessageTypeSyncResp,
				Data:    data,
				Version: ProtocolVersion,
			}
			s, err := n.Host.NewStream(context.Background(), peerID, "/blackhole/1.0.0")
			if err != nil {
				fmt.Printf("❌ Error opening stream to %s: %v\n", peerID, err)
				continue
			}
			if err := resp.Encode(s); err != nil {
				fmt.Printf("❌ Error encoding sync response to %s: %v\n", peerID, err)
				s.Close()
				continue
			}
			s.Close()
			fmt.Printf("📤 Sent block %d to peer %s\n", block.Header.Index, peerID)
		}
	case MessageTypeSyncResp:
		block, err := DeserializeBlock(msg.Data)
		if err != nil {
			if strings.Contains(err.Error(), "CommonType") {
				fmt.Printf("⚠️ Skipping sync block with CommonType reference from peer %s\n", peerID)
				n.disconnectPeer(peerID)
				return
			}
			fmt.Printf("❌ Error deserializing sync block from peer %s: %v\n", peerID, err)
			n.badPeersLock.Lock()
			n.badPeers[peerID]++
			if n.badPeers[peerID] >= 3 {
				n.disconnectPeer(peerID)
			}
			n.badPeersLock.Unlock()
			return
		}
		fmt.Printf("📑 Sync block details: Index=%d, Hash=%s, PrevHash=%s, Validator=%s, TxCount=%d\n",
			block.Header.Index, block.Hash, block.Header.PreviousHash, block.Header.Validator, len(block.Transactions))
		if n.chain.AddBlock(block) {
			fmt.Printf("🧱 Added sync block %d from peer %s\n", block.Header.Index, peerID)
			n.badPeersLock.Lock()
			n.badPeers[peerID] = 0
			n.badPeersLock.Unlock()
		} else {
			fmt.Printf("⚠️ Failed to add sync block %d from peer %s\n", block.Header.Index, peerID)
		}
	default:
		fmt.Printf("⚠️ Unknown message type received: %v\n", msg.Type)

	}
}

func (n *Node) Broadcast(msg *Message) {
	n.peersLock.RLock()
	defer n.peersLock.RUnlock()

	for peerID := range n.peers {
		s, err := n.Host.NewStream(context.Background(), peerID, "/blackhole/1.0.0")
		if err != nil {
			fmt.Printf("❌ Error opening stream to %s: %v\n", peerID, err)
			continue
		}
		msg.Version = ProtocolVersion
		if err := msg.Encode(s); err != nil {
			fmt.Printf("❌ Error encoding message to %s: %v\n", peerID, err)
			s.Close()
			continue
		}
		s.Close()
		fmt.Printf("📤 Broadcast message type %d to peer %s\n", msg.Type, peerID)
	}
}
