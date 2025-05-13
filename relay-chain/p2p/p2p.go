package p2p

import (
	"context"
	"encoding/gob"
	"fmt"
	"sync"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"

	"github.com/Shivam-Patel-G/blackhole-blockchain/relay-chain/chain"
)

func init() {
	gob.Register(&chain.Transaction{})
	gob.Register(&chain.Block{})
	gob.Register(&chain.StakeLedger{})
}

type Node struct {
	Host      host.Host
	peers     map[peer.ID]*peer.AddrInfo
	peersLock sync.RWMutex
	chain     *chain.Blockchain
}

func NewNode(ctx context.Context, port int) (*Node, error) {
	h, err := libp2p.New(
		libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", port)),
	)
	if err != nil {
		return nil, err
	}

	node := &Node{
		Host:  h,
		peers: make(map[peer.ID]*peer.AddrInfo),
	}

	h.SetStreamHandler("/blackhole/1.0.0", node.handleStream)

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

	n.Host.Connect(ctx, *info)
	n.peersLock.Lock()
	n.peers[info.ID] = info
	n.peersLock.Unlock()
	return nil
}

func (n *Node) SetChain(bc *chain.Blockchain) {
	n.chain = bc
}

func (n *Node) handleStream(s network.Stream) {
	defer s.Close()

	var msg Message
	if err := msg.Decode(s); err != nil {
		fmt.Printf("Error decoding message: %v\n", err)
		return
	}

	switch msg.Type {
	case MessageTypeTx:
		tx, err := DeserializeTransaction(msg.Data)
		if err != nil {
			fmt.Printf("Error deserializing transaction: %v\n", err)
			return
		}
		if tx.Verify() {
			n.chain.PendingTxs = append(n.chain.PendingTxs, tx)
		}
	case MessageTypeBlock:
		block, err := DeserializeBlock(msg.Data)
		if err != nil {
			fmt.Printf("Error deserializing block: %v\n", err)
			return
		}
		if n.chain.AddBlock(block) {
			fmt.Printf("Added block %d from peer\n", block.Header.Index)
		}
	case MessageTypeSyncReq:
		for _, block := range n.chain.Blocks {
			data, _ := block.Serialize()
			resp := &Message{
				Type: MessageTypeSyncResp,
				Data: data.([]byte),
			}
			n.Broadcast(resp)
		}
	case MessageTypeSyncResp:
		block, err := DeserializeBlock(msg.Data)
		if err != nil {
			fmt.Printf("Error deserializing sync block: %v\n", err)
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
			fmt.Printf("Error opening stream to %s: %v\n", peerID, err)
			continue
		}
		if err := msg.Encode(s); err != nil {
			fmt.Printf("Error encoding message to %s: %v\n", peerID, err)
			s.Close()
			continue
		}
		s.Close()
	}
}