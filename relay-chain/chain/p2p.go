package chain

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

type Node struct {
	Host      host.Host
	peers     map[peer.ID]*peer.AddrInfo
	peersLock sync.RWMutex
	chain     *Blockchain
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
	listenAddr := fmt.Sprintf("/ip4/%s/tcp/%d", ip, port)

	h, err := libp2p.New(
		libp2p.ListenAddrStrings(listenAddr),
	)
	if err != nil {
		return nil, err
	}

	node := &Node{
		Host:  h,
		peers: make(map[peer.ID]*peer.AddrInfo),
	}

	h.SetStreamHandler("/blackhole/1.0.0", node.handleStream)

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

func (n *Node) handleStream(s network.Stream) {
	defer s.Close()

	peerID := s.Conn().RemotePeer()
	fmt.Printf("📡 Received stream from peer: %s\n", peerID) // Added peer ID logging

	var msg Message
	if err := msg.Decode(s); err != nil {
		fmt.Printf("❌ Error decoding message from peer %s: %v\n", peerID, err)
		return
	}

	switch msg.Type {
	case MessageTypeTx:
		tx, err := DeserializeTransaction(msg.Data)
		if err != nil {
			fmt.Printf("❌ Error deserializing transaction from peer %s: %v\n", peerID, err)
			return
		}
		if tx.Verify() {
			n.chain.PendingTxs = append(n.chain.PendingTxs, tx)
		}
	case MessageTypeBlock:
		block, err := DeserializeBlock(msg.Data)
		if err != nil {
			fmt.Printf("❌ Error deserializing block from peer %s: %v\n", peerID, err)
			return
		}
		if n.chain.AddBlock(block) {
			fmt.Printf("🧱 Added block %d from peer %s\n", block.Header.Index, peerID)
		}
	case MessageTypeSyncReq:
		for _, block := range n.chain.Blocks {
			data := block.Serialize()
			resp := &Message{
				Type: MessageTypeSyncResp,
				Data: data,
			}
			n.Broadcast(resp)
		}
	case MessageTypeSyncResp:
		block, err := DeserializeBlock(msg.Data)
		if err != nil {
			fmt.Printf("❌ Error deserializing sync block from peer %s: %v\n", peerID, err)
			return
		}
		n.chain.AddBlock(block)
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
		if err := msg.Encode(s); err != nil {
			fmt.Printf("❌ Error encoding message to %s: %v\n", peerID, err)
			s.Close()
			continue
		}
		s.Close()
	}
}