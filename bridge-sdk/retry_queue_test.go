package bridgesdk

import (
	"testing"
	"time"
)

func TestRetryQueue_AddAndProcess(t *testing.T) {
	t.Parallel()
	rq := &RetryQueue{
		items: make([]RetryItem, 0),
	}
	called := 0
	rq.items = append(rq.items, RetryItem{
		ID:          "test1",
		Type:        "test",
		Data:        map[string]interface{}{"foo": "bar"},
		Attempts:    0,
		MaxAttempts: 3,
		NextRetry:   time.Now().Add(-1 * time.Second),
		CreatedAt:   time.Now(),
	})
	// Simulate processor that fails twice, then succeeds
	processor := func(item RetryItem) error {
		called++
		if called < 3 {
			return &testError{"fail"}
		}
		return nil
	}
	// Process retries until item is removed
	for i := 0; i < 5; i++ {
		rq.processItems(processor)
		time.Sleep(10 * time.Millisecond)
	}
	if called != 3 {
		t.Errorf("expected 3 calls, got %d", called)
	}
	if len(rq.items) != 0 {
		t.Errorf("expected 0 items after success, got %d", len(rq.items))
	}
}

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }

func TestRetryQueue_MaxRetries(t *testing.T) {
	t.Parallel()
	rq := &RetryQueue{
		items: make([]RetryItem, 0),
	}
	rq.items = append(rq.items, RetryItem{
		ID:          "test2",
		Type:        "test",
		Data:        map[string]interface{}{"foo": "bar"},
		Attempts:    0,
		MaxAttempts: 2,
		NextRetry:   time.Now().Add(-1 * time.Second),
		CreatedAt:   time.Now(),
	})
	failProcessor := func(item RetryItem) error { return &testError{"fail"} }
	for i := 0; i < 5; i++ {
		rq.processItems(failProcessor)
		time.Sleep(10 * time.Millisecond)
	}
	if len(rq.items) != 0 {
		t.Errorf("expected 0 items after max retries, got %d", len(rq.items))
	}
}

func TestRetryQueue_ExponentialBackoff(t *testing.T) {
	t.Parallel()
	rq := &RetryQueue{
		items: make([]RetryItem, 0),
	}
	maxAttempts := 5
	rq.items = append(rq.items, RetryItem{
		ID:          "test3",
		Type:        "test",
		Data:        map[string]interface{}{"foo": "bar"},
		Attempts:    0,
		MaxAttempts: maxAttempts,
		NextRetry:   time.Now().Add(-1 * time.Second),
		CreatedAt:   time.Now(),
	})
	item := &rq.items[0]
	for i := 1; i <= maxAttempts; i++ {
		delay := time.Duration(i*i) * time.Second
		item.Attempts = i
		item.NextRetry = time.Now().Add(delay)
		if item.NextRetry.Sub(time.Now()) < delay-10*time.Millisecond || item.NextRetry.Sub(time.Now()) > delay+10*time.Millisecond {
			t.Errorf("delay not as expected: got %v, want %v", item.NextRetry.Sub(time.Now()), delay)
		}
	}
}
