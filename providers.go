package anticaptcha

import "context"

type IProvider interface {
	// SolveImageCaptcha is the implementation of getting the response of an image captcha
	SolveImageCaptcha(ctx context.Context, settings *Settings, payload *ImageCaptchaPayload) (ICaptchaResponse, error)

	// SolveRecaptchaV2 is the implementation of getting the response of a version 2 recaptcha
	SolveRecaptchaV2(ctx context.Context, settings *Settings, payload *RecaptchaV2Payload) (ICaptchaResponse, error)

	// SolveRecaptchaV3 is the implementation of getting the response of a version 3 recaptcha
	SolveRecaptchaV3(ctx context.Context, settings *Settings, payload *RecaptchaV3Payload) (ICaptchaResponse, error)

	// SolveHCaptcha is the implementation of getting the response of an HCaptcha captcha
	SolveHCaptcha(ctx context.Context, settings *Settings, payload *HCaptchaPayload) (ICaptchaResponse, error)

	// SolveTurnstile is the implementation of getting a turnstile token
	SolveTurnstile(ctx context.Context, settings *Settings, payload *TurnstilePayload) (ICaptchaResponse, error)

	// SolveCoordinates is the implementation of getting the response of an coordinates captcha
	SolveCoordinates(ctx context.Context, settings *Settings, payload *CoordinatesPayload) (ICaptchaResponse, error)

	// SolveCustom is the implementation of getting the response of an any type of captcha with arbitray fields
	SolveCustom(ctx context.Context, settings *Settings, payload *CustomPayload) (ICaptchaResponse, error)
}
