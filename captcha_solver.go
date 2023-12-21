package anticaptcha

import (
	"context"
	"net/http"
	"time"
)

type CaptchaSolver struct {
	provider IProvider
	settings *Settings
}

func NewCaptchaSolver(provider IProvider) *CaptchaSolver {
	return &CaptchaSolver{
		settings: NewSettings(),
		provider: provider,
	}
}

func (c *CaptchaSolver) SolveImageCaptcha(ctx context.Context, payload *ImageCaptchaPayload) (ICaptchaResponse, error) {
	return c.provider.SolveImageCaptcha(ctx, c.settings, payload)
}

func (c *CaptchaSolver) SolveRecaptchaV2(ctx context.Context, payload *RecaptchaV2Payload) (ICaptchaResponse, error) {
	return c.provider.SolveRecaptchaV2(ctx, c.settings, payload)
}

func (c *CaptchaSolver) SolveRecaptchaV3(ctx context.Context, payload *RecaptchaV3Payload) (ICaptchaResponse, error) {
	return c.provider.SolveRecaptchaV3(ctx, c.settings, payload)
}

func (c *CaptchaSolver) SolveHCaptcha(ctx context.Context, payload *HCaptchaPayload) (ICaptchaResponse, error) {
	return c.provider.SolveHCaptcha(ctx, c.settings, payload)
}

func (c *CaptchaSolver) SolveTurnstile(ctx context.Context, payload *TurnstilePayload) (ICaptchaResponse, error) {
	return c.provider.SolveTurnstile(ctx, c.settings, payload)
}

func (c *CaptchaSolver) SolveCoordinates(ctx context.Context, payload *CoordinatesPayload) (ICaptchaResponse, error) {
	return c.provider.SolveCoordinates(ctx, c.settings, payload)
}

func (c *CaptchaSolver) SolveCustom(ctx context.Context, payload *CustomPayload) (ICaptchaResponse, error) {
	return c.provider.SolveCustom(ctx, c.settings, payload)
}

// SetClient will set the client that is used when interacting with APIs of providers.
func (c *CaptchaSolver) SetClient(client *http.Client) {
	c.settings.client = client
}

// SetInitialWaitTime sets the time that is being waited after submitting a task to a provider before polling
func (c *CaptchaSolver) SetInitialWaitTime(waitTime time.Duration) {
	c.settings.initialWaitTime = waitTime
}

// SetPollInterval sets the time that is being waited in between result polls
func (c *CaptchaSolver) SetPollInterval(interval time.Duration) {
	c.settings.pollInterval = interval
}

// SetMaxRetries sets the maximum amount of polling
func (c *CaptchaSolver) SetMaxRetries(maxRetries int) {
	c.settings.maxRetries = maxRetries
}
