package storage

import (
	"encoding/json"
	"fmt"
	"time"

	"go.etcd.io/bbolt"

	"github.com/Shivam-Patel-G/blackhole-blockchain/bridge-sdk/core"
)

// Storage is the interface for persistent storage
type Storage interface {
	SaveTransaction(tx *core.Transaction) error
	GetTransaction(id string) (*core.Transaction, error)
	MarkProcessed(hash string) error
	IsProcessed(hash string) bool
	SaveRetryItem(item *core.RetryItem) error
	GetRetryQueue() ([]*core.RetryItem, error)
	SaveEvent(event *core.Event) error
	GetEvents(limit int) ([]*core.Event, error)
	Close() error
}

// BoltStorage implements Storage using BoltDB
type BoltStorage struct {
	db *bbolt.DB
}

// NewBoltStorage creates a new BoltDB storage instance
func NewBoltStorage(path string) (*BoltStorage, error) {
	db, err := bbolt.Open(path, 0600, &bbolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("failed to open BoltDB: %w", err)
	}

	// Create buckets
	err = db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("transactions"))
		if err != nil {
			return err
		}
		_, err = tx.CreateBucketIfNotExists([]byte("replay_protection"))
		if err != nil {
			return err
		}
		_, err = tx.CreateBucketIfNotExists([]byte("retry_queue"))
		if err != nil {
			return err
		}
		_, err = tx.CreateBucketIfNotExists([]byte("events"))
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}

	return &BoltStorage{db: db}, nil
}

func (bs *BoltStorage) SaveTransaction(tx *core.Transaction) error {
	return bs.db.Update(func(boltTx *bbolt.Tx) error {
		bucket := boltTx.Bucket([]byte("transactions"))
		if bucket == nil {
			return fmt.Errorf("transactions bucket not found")
		}
		data, err := json.Marshal(tx)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(tx.ID), data)
	})
}

func (bs *BoltStorage) GetTransaction(id string) (*core.Transaction, error) {
	var tx core.Transaction
	err := bs.db.View(func(boltTx *bbolt.Tx) error {
		bucket := boltTx.Bucket([]byte("transactions"))
		if bucket == nil {
			return fmt.Errorf("transactions bucket not found")
		}
		data := bucket.Get([]byte(id))
		if data == nil {
			return fmt.Errorf("transaction not found")
		}
		return json.Unmarshal(data, &tx)
	})
	if err != nil {
		return nil, err
	}
	return &tx, nil
}

func (bs *BoltStorage) MarkProcessed(hash string) error {
	return bs.db.Update(func(boltTx *bbolt.Tx) error {
		bucket := boltTx.Bucket([]byte("replay_protection"))
		if bucket == nil {
			return fmt.Errorf("replay_protection bucket not found")
		}
		timestamp := time.Now().Unix()
		value := []byte(fmt.Sprintf("%d", timestamp))
		return bucket.Put([]byte(hash), value)
	})
}

func (bs *BoltStorage) IsProcessed(hash string) bool {
	var exists bool
	bs.db.View(func(boltTx *bbolt.Tx) error {
		bucket := boltTx.Bucket([]byte("replay_protection"))
		if bucket != nil {
			value := bucket.Get([]byte(hash))
			exists = value != nil
		}
		return nil
	})
	return exists
}

func (bs *BoltStorage) SaveRetryItem(item *core.RetryItem) error {
	return bs.db.Update(func(boltTx *bbolt.Tx) error {
		bucket := boltTx.Bucket([]byte("retry_queue"))
		if bucket == nil {
			return fmt.Errorf("retry_queue bucket not found")
		}
		data, err := json.Marshal(item)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(item.ID), data)
	})
}

func (bs *BoltStorage) GetRetryQueue() ([]*core.RetryItem, error) {
	var items []*core.RetryItem
	err := bs.db.View(func(boltTx *bbolt.Tx) error {
		bucket := boltTx.Bucket([]byte("retry_queue"))
		if bucket == nil {
			return nil
		}
		c := bucket.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var item core.RetryItem
			if err := json.Unmarshal(v, &item); err != nil {
				continue
			}
			items = append(items, &item)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return items, nil
}

func (bs *BoltStorage) SaveEvent(event *core.Event) error {
	return bs.db.Update(func(boltTx *bbolt.Tx) error {
		bucket := boltTx.Bucket([]byte("events"))
		if bucket == nil {
			return fmt.Errorf("events bucket not found")
		}
		data, err := json.Marshal(event)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(event.ID), data)
	})
}

func (bs *BoltStorage) GetEvents(limit int) ([]*core.Event, error) {
	var events []*core.Event
	err := bs.db.View(func(boltTx *bbolt.Tx) error {
		bucket := boltTx.Bucket([]byte("events"))
		if bucket == nil {
			return nil
		}
		c := bucket.Cursor()
		count := 0
		for k, v := c.Last(); k != nil && count < limit; k, v = c.Prev() {
			var event core.Event
			if err := json.Unmarshal(v, &event); err != nil {
				continue
			}
			events = append(events, &event)
			count++
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return events, nil
}

func (bs *BoltStorage) Close() error {
	return bs.db.Close()
}