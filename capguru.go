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

type CapGuruCaptcha struct {
	baseUrl string
	apiKey  string
}

type CapGuruCaptchaResponse struct {
	Status    int    `json:"status"`
	Request   string `json:"request"`
	ErrorText string `json:"error_text"`
}

func NewCapGuruCaptcha(apiKey string) *CapGuruCaptcha {
	return &CapGuruCaptcha{
		apiKey:  apiKey,
		baseUrl: "http://api.cap.guru",
	}
}

// NewCustomCapGuruCaptcha can be used to change the baseUrl, some providers such as CapMonster, XEVil and CapSolver
// have the exact same API as CapGuruCaptcha, thus allowing you to use these providers with ease.
func NewCustomCapGuruCaptcha(baseUrl, apiKey string) *CapGuruCaptcha {
	return &CapGuruCaptcha{
		baseUrl: baseUrl,
		apiKey:  apiKey,
	}
}

func (a *CapGuruCaptcha) SolveImageCaptcha(ctx context.Context, settings *Settings, payload *ImageCaptchaPayload) (ICaptchaResponse, error) {
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

func (a *CapGuruCaptcha) SolveRecaptchaV2(ctx context.Context, settings *Settings, payload *RecaptchaV2Payload) (ICaptchaResponse, error) {
	return nil, fmt.Errorf("Captcha doesn't support")
}

func (a *CapGuruCaptcha) SolveRecaptchaV3(ctx context.Context, settings *Settings, payload *RecaptchaV3Payload) (ICaptchaResponse, error) {
	return nil, fmt.Errorf("Captcha doesn't support")
}

func (a *CapGuruCaptcha) SolveHCaptcha(ctx context.Context, settings *Settings, payload *HCaptchaPayload) (ICaptchaResponse, error) {
	return nil, fmt.Errorf("Captcha doesn't support")
}

func (a *CapGuruCaptcha) SolveTurnstile(ctx context.Context, settings *Settings, payload *TurnstilePayload) (ICaptchaResponse, error) {
	return nil, fmt.Errorf("Captcha doesn't support")
}

func (a *CapGuruCaptcha) SolveCoordinates(ctx context.Context, settings *Settings, payload *CoordinatesPayload) (ICaptchaResponse, error) {
	return nil, fmt.Errorf("Captcha doesn't support")
}

func (a *CapGuruCaptcha) SolveCustom(ctx context.Context, settings *Settings, payload *CustomPayload) (ICaptchaResponse, error) {
	result, err := a.solveTask(ctx, settings, payload.Params)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (a *CapGuruCaptcha) solveTask(ctx context.Context, settings *Settings, task map[string]any) (*CaptchaResponse, error) {
	answer, err := a.createTaskInstantResult(ctx, settings, task)
	if err != nil {
		return nil, err
	}

	if err := internal.SleepWithContext(ctx, settings.initialWaitTime); err != nil {
		return nil, err
	}

	if answer != "" {
		return &CaptchaResponse{solution: answer, taskId: ""}, nil
	}

	return nil, errors.New("error")
}

func (a *CapGuruCaptcha) createTaskInstantResult(ctx context.Context, settings *Settings, task map[string]any) (string, error) {
	task["key"] = a.apiKey
	task["json"] = 1
	jsonValue, err := json.Marshal(task)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseUrl, bytes.NewBuffer(jsonValue))
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

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return string(respBody), nil
}

// nolint
func (a *CapGuruCaptcha) createTask(ctx context.Context, settings *Settings, task map[string]any) (string, error) {
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

	var responseAsJSON CapGuruCaptchaResponse
	if err := json.Unmarshal(respBody, &responseAsJSON); err != nil {
		return "", err
	}

	if responseAsJSON.Status == 0 {
		return "", fmt.Errorf("%v", responseAsJSON.Request)
	}

	return responseAsJSON.Request, nil
}

// nolint
func (a *CapGuruCaptcha) getResult(ctx context.Context, settings *Settings, taskId string) (string, error) {
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

func (t *CapGuruCaptcha) Report(ctx context.Context, action, taskId string, settings *Settings) error {
	return nil
}

var _ IProvider = (*CapGuruCaptcha)(nil)
