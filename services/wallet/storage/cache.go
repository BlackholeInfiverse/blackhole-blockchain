package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"
)

// Redis cache helper methods

func (s *Service) cacheUser(user *User) {
	if s.manager.Redis == nil {
		return
	}

	ctx := context.Background()
	
	// Cache user by username
	userKey := fmt.Sprintf("user:username:%s", user.Username)
	userData, err := json.Marshal(user)
	if err != nil {
		log.Printf("Failed to marshal user for cache: %v", err)
		return
	}

	// Cache for 30 minutes
	if err := s.manager.Redis.Set(ctx, userKey, userData, 30*time.Minute).Err(); err != nil {
		log.Printf("Failed to cache user: %v", err)
	}

	// Also cache by ID
	userIDKey := fmt.Sprintf("user:id:%d", user.ID)
	if err := s.manager.Redis.Set(ctx, userIDKey, userData, 30*time.Minute).Err(); err != nil {
		log.Printf("Failed to cache user by ID: %v", err)
	}
}

func (s *Service) getCachedUser(username string) *User {
	if s.manager.Redis == nil {
		return nil
	}

	ctx := context.Background()
	userKey := fmt.Sprintf("user:username:%s", username)
	
	data, err := s.manager.Redis.Get(ctx, userKey).Result()
	if err != nil {
		return nil // Cache miss or error
	}

	var user User
	if err := json.Unmarshal([]byte(data), &user); err != nil {
		log.Printf("Failed to unmarshal cached user: %v", err)
		return nil
	}

	return &user
}

func (s *Service) cacheSession(session *Session) {
	if s.manager.Redis == nil {
		return
	}

	ctx := context.Background()
	sessionKey := fmt.Sprintf("session:%s", session.SessionID)
	
	sessionData, err := json.Marshal(session)
	if err != nil {
		log.Printf("Failed to marshal session for cache: %v", err)
		return
	}

	// Cache until session expires
	ttl := time.Until(session.ExpiresAt)
	if ttl > 0 {
		if err := s.manager.Redis.Set(ctx, sessionKey, sessionData, ttl).Err(); err != nil {
			log.Printf("Failed to cache session: %v", err)
		}
	}
}

func (s *Service) getCachedSession(sessionID string) *Session {
	if s.manager.Redis == nil {
		return nil
	}

	ctx := context.Background()
	sessionKey := fmt.Sprintf("session:%s", sessionID)
	
	data, err := s.manager.Redis.Get(ctx, sessionKey).Result()
	if err != nil {
		return nil // Cache miss or error
	}

	var session Session
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		log.Printf("Failed to unmarshal cached session: %v", err)
		return nil
	}

	// Double-check session is not expired
	if session.ExpiresAt.Before(time.Now().UTC()) {
		s.removeCachedSession(sessionID)
		return nil
	}

	return &session
}

func (s *Service) removeCachedSession(sessionID string) {
	if s.manager.Redis == nil {
		return
	}

	ctx := context.Background()
	sessionKey := fmt.Sprintf("session:%s", sessionID)
	
	if err := s.manager.Redis.Del(ctx, sessionKey).Err(); err != nil {
		log.Printf("Failed to remove cached session: %v", err)
	}
}

func (s *Service) cacheWalletBalance(address string, balance float64) {
	if s.manager.Redis == nil {
		return
	}

	ctx := context.Background()
	balanceKey := fmt.Sprintf("wallet:balance:%s", address)
	
	// Cache balance for 5 minutes
	if err := s.manager.Redis.Set(ctx, balanceKey, balance, 5*time.Minute).Err(); err != nil {
		log.Printf("Failed to cache wallet balance: %v", err)
	}
}

func (s *Service) getCachedWalletBalance(address string) (float64, bool) {
	if s.manager.Redis == nil {
		return 0, false
	}

	ctx := context.Background()
	balanceKey := fmt.Sprintf("wallet:balance:%s", address)
	
	balance, err := s.manager.Redis.Get(ctx, balanceKey).Float64()
	if err != nil {
		return 0, false
	}

	return balance, true
}

// Cache invalidation methods
func (s *Service) invalidateUserCache(username string, userID uint) {
	if s.manager.Redis == nil {
		return
	}

	ctx := context.Background()
	
	// Remove user cache by username
	userKey := fmt.Sprintf("user:username:%s", username)
	s.manager.Redis.Del(ctx, userKey)

	// Remove user cache by ID
	userIDKey := fmt.Sprintf("user:id:%d", userID)
	s.manager.Redis.Del(ctx, userIDKey)
}
