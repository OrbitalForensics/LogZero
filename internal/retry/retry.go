package retry

import (
	"context"
	"errors"
	"math"
	"math/rand"
	"time"

	"LogZero/internal/logger"
)

// DefaultRetryConfig provides default configuration for retry operations
var DefaultRetryConfig = RetryConfig{
	MaxAttempts:      5,
	InitialBackoff:   100 * time.Millisecond,
	MaxBackoff:       5 * time.Second,
	BackoffFactor:    2.0,
	RandomizationFactor: 0.5,
}

// RetryConfig configures the retry behavior
type RetryConfig struct {
	// MaxAttempts is the maximum number of attempts including the first attempt
	MaxAttempts int
	
	// InitialBackoff is the initial backoff duration
	InitialBackoff time.Duration
	
	// MaxBackoff is the maximum backoff duration
	MaxBackoff time.Duration
	
	// BackoffFactor is the factor by which the backoff increases
	BackoffFactor float64
	
	// RandomizationFactor is the factor by which the backoff is randomized
	RandomizationFactor float64
}

// WithRetry executes the given function with retry logic
func WithRetry(operation string, fn func() error) error {
	return WithRetryConfig(operation, DefaultRetryConfig, fn)
}

// WithRetryConfig executes the given function with retry logic using the provided config
func WithRetryConfig(operation string, config RetryConfig, fn func() error) error {
	var err error
	
	// Initialize random number generator
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	
	// Execute the function with retries
	for attempt := 1; attempt <= config.MaxAttempts; attempt++ {
		// Execute the function
		err = fn()
		
		// If successful or reached max attempts, return
		if err == nil {
			return nil
		}
		
		// If this was the last attempt, return the error
		if attempt == config.MaxAttempts {
			logger.Error("Failed %s after %d attempts: %v", operation, attempt, err)
			return err
		}
		
		// Calculate backoff duration
		backoff := calculateBackoff(attempt, config, r)
		
		// Log retry attempt
		logger.Warn("Retrying %s (attempt %d/%d) after %v: %v", 
			operation, attempt, config.MaxAttempts, backoff, err)
		
		// Wait for backoff duration
		time.Sleep(backoff)
	}
	
	// This should never happen, but just in case
	return errors.New("unexpected error in retry logic")
}

// WithRetryContext executes the given function with retry logic and respects context cancellation
func WithRetryContext(ctx context.Context, operation string, fn func() error) error {
	return WithRetryContextConfig(ctx, operation, DefaultRetryConfig, fn)
}

// WithRetryContextConfig executes the given function with retry logic using the provided config
// and respects context cancellation
func WithRetryContextConfig(ctx context.Context, operation string, config RetryConfig, fn func() error) error {
	var err error
	
	// Initialize random number generator
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	
	// Execute the function with retries
	for attempt := 1; attempt <= config.MaxAttempts; attempt++ {
		// Check if context is cancelled
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			// Continue with retry
		}
		
		// Execute the function
		err = fn()
		
		// If successful or reached max attempts, return
		if err == nil {
			return nil
		}
		
		// If this was the last attempt, return the error
		if attempt == config.MaxAttempts {
			logger.Error("Failed %s after %d attempts: %v", operation, attempt, err)
			return err
		}
		
		// Calculate backoff duration
		backoff := calculateBackoff(attempt, config, r)
		
		// Log retry attempt
		logger.Warn("Retrying %s (attempt %d/%d) after %v: %v", 
			operation, attempt, config.MaxAttempts, backoff, err)
		
		// Wait for backoff duration with context cancellation support
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
			// Continue with retry
		}
	}
	
	// This should never happen, but just in case
	return errors.New("unexpected error in retry logic")
}

// calculateBackoff calculates the backoff duration for a given attempt
func calculateBackoff(attempt int, config RetryConfig, r *rand.Rand) time.Duration {
	// Calculate backoff using exponential backoff formula
	backoff := float64(config.InitialBackoff) * math.Pow(config.BackoffFactor, float64(attempt-1))
	
	// Apply randomization factor
	delta := config.RandomizationFactor * backoff
	min := backoff - delta
	max := backoff + delta
	
	// Get random backoff between min and max
	backoff = min + (max-min)*r.Float64()
	
	// Ensure backoff doesn't exceed max backoff
	if backoff > float64(config.MaxBackoff) {
		backoff = float64(config.MaxBackoff)
	}
	
	return time.Duration(backoff)
}