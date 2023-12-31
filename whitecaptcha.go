package anticaptcha

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/packman80/anticaptcha/internal"
)

type WhiteCaptcha struct {
	baseUrl string
	apiKey  string
}

type Response struct {
	Status    int    `json:"status"`
	Request   string `json:"request"`
	ErrorText string `json:"error_text"`
}

func NewWhiteCaptcha(apiKey string) *WhiteCaptcha {
	return &WhiteCaptcha{
		apiKey:  apiKey,
		baseUrl: "http://api.white-captcha.com",
	}
}

// NewCustomWhiteCaptcha can be used to change the baseUrl, some providers such as CapMonster, XEVil and CapSolver
// have the exact same API as WhiteCaptcha, thus allowing you to use these providers with ease.
func NewCustomWhiteCaptcha(baseUrl, apiKey string) *WhiteCaptcha {
	return &WhiteCaptcha{
		baseUrl: baseUrl,
		apiKey:  apiKey,
	}
}

func (a *WhiteCaptcha) SolveImageCaptcha(ctx context.Context, settings *Settings, payload *ImageCaptchaPayload) (ICaptchaResponse, error) {
	task := map[string]any{
		"type": "ImageToTextTask",
		"body": payload.Base64String,
		"case": payload.CaseSensitive,
	}

	result, err := a.solveTask(ctx, settings, task)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (a *WhiteCaptcha) SolveRecaptchaV2(ctx context.Context, settings *Settings, payload *RecaptchaV2Payload) (ICaptchaResponse, error) {
	return nil, fmt.Errorf("Captcha doesn't support")
}

func (a *WhiteCaptcha) SolveRecaptchaV3(ctx context.Context, settings *Settings, payload *RecaptchaV3Payload) (ICaptchaResponse, error) {
	return nil, fmt.Errorf("Captcha doesn't support")
}

func (a *WhiteCaptcha) SolveHCaptcha(ctx context.Context, settings *Settings, payload *HCaptchaPayload) (ICaptchaResponse, error) {
	return nil, fmt.Errorf("Captcha doesn't support")
}

func (a *WhiteCaptcha) SolveTurnstile(ctx context.Context, settings *Settings, payload *TurnstilePayload) (ICaptchaResponse, error) {
	return nil, fmt.Errorf("Captcha doesn't support")
}

func (a *WhiteCaptcha) SolveCoordinates(ctx context.Context, settings *Settings, payload *CoordinatesPayload) (ICaptchaResponse, error) {
	return nil, fmt.Errorf("Captcha doesn't support")
}

func (a *WhiteCaptcha) SolveCustom(ctx context.Context, settings *Settings, payload *CustomPayload) (ICaptchaResponse, error) {
	result, err := a.solveTask(ctx, settings, payload.Params)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (a *WhiteCaptcha) solveTask(ctx context.Context, settings *Settings, task map[string]any) (*CaptchaResponse, error) {
	taskId, err := a.createTask(ctx, settings, task)
	if err != nil {
		return nil, err
	}

	if err := internal.SleepWithContext(ctx, settings.initialWaitTime); err != nil {
		return nil, err
	}

	for i := 0; i < settings.maxRetries; i++ {
		answer, err := a.getResult(ctx, settings, taskId)
		if err != nil {
			return nil, err
		}

		if answer != "" {
			return &CaptchaResponse{solution: answer, taskId: taskId}, nil
		}

		if err := internal.SleepWithContext(ctx, settings.pollInterval); err != nil {
			return nil, err
		}
	}

	return nil, errors.New("max tries exceeded")
}

func (a *WhiteCaptcha) createTask(ctx context.Context, settings *Settings, task map[string]any) (string, error) {
	task["key"] = a.apiKey
	task["json"] = 1
	jsonValue, err := json.Marshal(task)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseUrl+"/in.php", bytes.NewBuffer(jsonValue))
	if err != nil {
		return "", err
	}
	req.Header.Set("content-type", "application/json")

	resp, err := settings.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var responseAsJSON Response
	if err := json.Unmarshal(respBody, &responseAsJSON); err != nil {
		return "", err
	}

	if responseAsJSON.Status == 0 {
		return "", fmt.Errorf("%v", responseAsJSON.Request)
	}

	return responseAsJSON.Request, nil
}

func (a *WhiteCaptcha) getResult(ctx context.Context, settings *Settings, taskId string) (string, error) {
	body := &url.Values{}
	body.Set("key", a.apiKey)
	body.Set("json", "1")
	body.Set("id", taskId)

	fullURL := fmt.Sprintf("%v/res.php?%v", a.baseUrl, body.Encode())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := settings.client.Do(req)
	if err != nil {
		return "", nil
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var respJson Response
	if err := json.Unmarshal(respBody, &respJson); err != nil {
		return "", err
	}

	if respJson.Status == 0 {
		if respJson.Request == "CAPCHA_NOT_READY" {
			return "", nil
		}

		return "", fmt.Errorf("%v", respJson.Request)
	}
	return respJson.Request, nil
}

func (t *WhiteCaptcha) Report(ctx context.Context, action, taskId string, settings *Settings) error {
	body := url.Values{}
	body.Set("key", t.apiKey)
	body.Set("action", action)
	body.Set("id", taskId)

	fullURL := fmt.Sprintf("%s/res.php?%s", t.baseUrl, body.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return err
	}

	resp, err := settings.client.Do(req)
	if err != nil {
		return err
	}

	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	return nil
}

var _ IProvider = (*WhiteCaptcha)(nil)
