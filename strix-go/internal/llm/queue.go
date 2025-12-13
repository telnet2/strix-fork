// Package llm provides LLM client implementation using eino
package llm

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/cloudwego/eino/schema"
)

// RequestQueue manages LLM request queueing with rate limiting and retries
type RequestQueue struct {
	mu sync.Mutex

	maxConcurrent int
	requestDelay  time.Duration
	maxRetries    int
	semaphore     chan struct{}
	lastRequest   time.Time
	closed        bool
}

// NewRequestQueue creates a new request queue
func NewRequestQueue(maxConcurrent int, requestDelay time.Duration, maxRetries int) *RequestQueue {
	if maxConcurrent <= 0 {
		maxConcurrent = 1
	}
	if maxRetries <= 0 {
		maxRetries = 3
	}

	return &RequestQueue{
		maxConcurrent: maxConcurrent,
		requestDelay:  requestDelay,
		maxRetries:    maxRetries,
		semaphore:     make(chan struct{}, maxConcurrent),
	}
}

// Execute executes a function with rate limiting and retries
func (q *RequestQueue) Execute(ctx context.Context, fn func() (*schema.Message, error)) (*schema.Message, error) {
	// Acquire semaphore
	select {
	case q.semaphore <- struct{}{}:
		defer func() { <-q.semaphore }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Apply rate limiting delay
	q.mu.Lock()
	if !q.lastRequest.IsZero() {
		elapsed := time.Since(q.lastRequest)
		if elapsed < q.requestDelay {
			sleepTime := q.requestDelay - elapsed
			q.mu.Unlock()
			select {
			case <-time.After(sleepTime):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			q.mu.Lock()
		}
	}
	q.lastRequest = time.Now()
	q.mu.Unlock()

	// Execute with retries
	var lastErr error
	for attempt := 0; attempt < q.maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff: 8s, 16s, 32s, 64s
			backoff := time.Duration(math.Pow(2, float64(attempt+2))) * time.Second
			if backoff > 64*time.Second {
				backoff = 64 * time.Second
			}

			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		result, err := fn()
		if err == nil {
			return result, nil
		}

		lastErr = err

		// Check if error is retryable
		if !isRetryableError(err) {
			return nil, err
		}
	}

	return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
}

// ExecuteStream executes a streaming function with rate limiting
func (q *RequestQueue) ExecuteStream(ctx context.Context, fn func() (*schema.StreamReader[*schema.Message], error)) (*schema.StreamReader[*schema.Message], error) {
	// Acquire semaphore
	select {
	case q.semaphore <- struct{}{}:
		// Note: For streaming, we don't release until stream is closed
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Apply rate limiting delay
	q.mu.Lock()
	if !q.lastRequest.IsZero() {
		elapsed := time.Since(q.lastRequest)
		if elapsed < q.requestDelay {
			sleepTime := q.requestDelay - elapsed
			q.mu.Unlock()
			select {
			case <-time.After(sleepTime):
			case <-ctx.Done():
				<-q.semaphore
				return nil, ctx.Err()
			}
			q.mu.Lock()
		}
	}
	q.lastRequest = time.Now()
	q.mu.Unlock()

	stream, err := fn()
	if err != nil {
		<-q.semaphore
		return nil, err
	}

	// Wrap stream to release semaphore when closed
	wrappedStream := wrapStreamWithRelease(stream, q.semaphore)
	return wrappedStream, nil
}

// Close closes the request queue
func (q *RequestQueue) Close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.closed = true
	close(q.semaphore)
}

// isRetryableError checks if an error is retryable
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()

	// Rate limit errors
	if contains(errStr, "rate limit") || contains(errStr, "429") {
		return true
	}

	// Timeout errors
	if contains(errStr, "timeout") || contains(errStr, "deadline exceeded") {
		return true
	}

	// Server errors
	if contains(errStr, "500") || contains(errStr, "502") || contains(errStr, "503") || contains(errStr, "504") {
		return true
	}

	// Connection errors
	if contains(errStr, "connection") || contains(errStr, "network") {
		return true
	}

	return false
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// wrapStreamWithRelease wraps a stream to release semaphore when closed
func wrapStreamWithRelease(stream *schema.StreamReader[*schema.Message], semaphore chan struct{}) *schema.StreamReader[*schema.Message] {
	// Create a new stream that wraps the original
	reader, writer := schema.Pipe[*schema.Message](10)

	go func() {
		defer func() {
			writer.Close()
			<-semaphore // Release semaphore when done
		}()

		for {
			msg, err := stream.Recv()
			if err != nil {
				if msg != nil {
					writer.Send(msg, nil)
				}
				writer.Send(nil, err)
				return
			}
			if writer.Send(msg, nil) {
				return // Writer closed
			}
		}
	}()

	return reader
}

// MemoryCompressor compresses conversation history to fit within token limits
type MemoryCompressor struct {
	maxTokens     int
	minMessages   int
	summaryModel  func(ctx context.Context, messages []*schema.Message) (string, error)
}

// NewMemoryCompressor creates a new memory compressor
func NewMemoryCompressor(maxTokens, minMessages int) *MemoryCompressor {
	return &MemoryCompressor{
		maxTokens:   maxTokens,
		minMessages: minMessages,
	}
}

// SetSummaryModel sets the function used to summarize messages
func (c *MemoryCompressor) SetSummaryModel(fn func(ctx context.Context, messages []*schema.Message) (string, error)) {
	c.summaryModel = fn
}

// Compress compresses the conversation history if needed
func (c *MemoryCompressor) Compress(ctx context.Context, messages []*schema.Message, currentTokens int) ([]*schema.Message, error) {
	// If under limit, return as-is
	threshold := int(float64(c.maxTokens) * 0.9)
	if currentTokens < threshold {
		return messages, nil
	}

	// Keep at least minMessages
	if len(messages) <= c.minMessages {
		return messages, nil
	}

	// Split into old and recent messages
	splitIndex := len(messages) - c.minMessages
	oldMessages := messages[:splitIndex]
	recentMessages := messages[splitIndex:]

	// If no summary model, just keep recent messages
	if c.summaryModel == nil {
		return recentMessages, nil
	}

	// Summarize old messages
	summary, err := c.summaryModel(ctx, oldMessages)
	if err != nil {
		// On error, just keep recent messages
		return recentMessages, nil
	}

	// Create summary message and prepend to recent messages
	summaryMsg := schema.SystemMessage(fmt.Sprintf("[Previous conversation summary]\n%s", summary))
	return append([]*schema.Message{summaryMsg}, recentMessages...), nil
}

// EstimateTokens provides a rough estimate of token count for messages
func EstimateTokens(messages []*schema.Message) int {
	total := 0
	for _, msg := range messages {
		// Rough estimate: ~4 characters per token
		total += len(msg.Content) / 4
		// Add overhead for message structure
		total += 10
	}
	return total
}
