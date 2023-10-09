package anticaptcha

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/packman80/anticaptcha/internal"
)

type TwoCaptcha struct {
	baseUrl string
	apiKey  string
}

func NewTwoCaptcha(apiKey string) *TwoCaptcha {
	return &TwoCaptcha{
		apiKey:  apiKey,
		baseUrl: "https://2captcha.com",
	}
}

// NewCustomTwoCaptcha can be used to change the baseUrl, some providers such as CapMonster, XEVil and CapSolver
// have the exact same API as AntiCaptcha, thus allowing you to use these providers with ease.
func NewCustomTwoCaptcha(baseUrl, apiKey string) *TwoCaptcha {
	return &TwoCaptcha{
		baseUrl: baseUrl,
		apiKey:  apiKey,
	}
}

func (t *TwoCaptcha) SolveImageCaptcha(ctx context.Context, settings *Settings, payload *ImageCaptchaPayload) (ICaptchaResponse, error) {
	task := &url.Values{}
	task.Set("method", "base64")
	task.Set("body", payload.Base64String)

	if payload.InstructionsForSolver != "" {
		task.Set("textinstructions", payload.InstructionsForSolver)
	}

	if payload.CaseSensitive {
		task.Set("regsense", "1")
	}

	result, err := t.solveTask(ctx, settings, task)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (t *TwoCaptcha) SolveRecaptchaV2(ctx context.Context, settings *Settings, payload *RecaptchaV2Payload) (ICaptchaResponse, error) {
	task := &url.Values{}
	task.Set("method", "userrecaptcha")
	task.Set("googlekey", payload.EndpointKey)
	task.Set("pageurl", payload.EndpointUrl)

	if payload.IsInvisibleCaptcha {
		task.Set("invisible", "1")
	}

	result, err := t.solveTask(ctx, settings, task)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (t *TwoCaptcha) SolveRecaptchaV3(ctx context.Context, settings *Settings, payload *RecaptchaV3Payload) (ICaptchaResponse, error) {
	task := &url.Values{}
	task.Set("method", "userrecaptcha")
	task.Set("version", "v3")
	task.Set("googlekey", payload.EndpointKey)
	task.Set("pageurl", payload.EndpointUrl)

	if payload.Action != "" {
		task.Set("action", payload.Action)
	}

	if payload.IsEnterprise {
		task.Set("enterprise", "1")
	}

	result, err := t.solveTask(ctx, settings, task)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (t *TwoCaptcha) SolveHCaptcha(ctx context.Context, settings *Settings, payload *HCaptchaPayload) (ICaptchaResponse, error) {
	task := &url.Values{}
	task.Set("method", "hcaptcha")
	task.Set("sitekey", payload.EndpointKey)
	task.Set("pageurl", payload.EndpointUrl)

	result, err := t.solveTask(ctx, settings, task)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (t *TwoCaptcha) SolveTurnstile(ctx context.Context, settings *Settings, payload *TurnstilePayload) (ICaptchaResponse, error) {
	task := &url.Values{}
	task.Set("method", "turnstile")
	task.Set("sitekey", payload.EndpointKey)
	task.Set("pageurl", payload.EndpointUrl)

	result, err := t.solveTask(ctx, settings, task)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (t *TwoCaptcha) SolveCoordinates(ctx context.Context, settings *Settings, payload *CoordinatesPayload) (ICaptchaResponse, error) {
	task := &url.Values{}
	task.Set("method", "base64")
	task.Set("coordinatescaptcha", "1")
	task.Set("body", payload.Body)
	task.Set("imginstructions", payload.ImageInstructions)

	result, err := t.solveTask(ctx, settings, task)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (t *TwoCaptcha) SolveCustom(ctx context.Context, settings *Settings, payload *CustomPayload) (ICaptchaResponse, error) {
	if len(payload.Params) == 0 {
		return nil, fmt.Errorf("Params for custom captcha are absent")
	}
	task := &url.Values{}
	for k, v := range payload.Params {
		switch val := v.(type) {
		case string:
			task.Set(k, val)
		case int:
			task.Set(k, strconv.Itoa(val))
		case int64:
			task.Set(k, strconv.FormatInt(val, 10))
		case float64:
			task.Set(k, strconv.FormatFloat(val, 'f', -1, 64))
		case float32:
			task.Set(k, strconv.FormatFloat(float64(val), 'f', -1, 32))
		default:
			return nil, fmt.Errorf("Unexpected type %T for key %s", v, k)
		}
	}

	result, err := t.solveTask(ctx, settings, task)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (t *TwoCaptcha) Report(ctx context.Context, action, taskId string, settings *Settings) error {
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

func (t *TwoCaptcha) solveTask(ctx context.Context, settings *Settings, task *url.Values) (*CaptchaResponse, error) {
	taskId, err := t.createTask(ctx, settings, task)
	if err != nil {
		return nil, err
	}

	if err := internal.SleepWithContext(ctx, settings.initialWaitTime); err != nil {
		return nil, err
	}

	for i := 0; i < settings.maxRetries; i++ {
		answer, err := t.getResult(ctx, settings, taskId)
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

func (t *TwoCaptcha) createTask(ctx context.Context, settings *Settings, payload *url.Values) (string, error) {
	type response struct {
		Status    int    `json:"status"`
		Request   string `json:"request"`
		ErrorText string `json:"error_text"`
	}

	payload.Set("key", t.apiKey)
	payload.Set("json", "1")

	fullURL := fmt.Sprintf("%v/in.php", t.baseUrl)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fullURL, strings.NewReader(payload.Encode()))
	if err != nil {
		return "", nil
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := settings.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var jsonResp response
	if err := json.Unmarshal(respBody, &jsonResp); err != nil {
		return "", err
	}

	if jsonResp.Status == 0 {
		return "", fmt.Errorf("%v: %v", jsonResp.Request, jsonResp.ErrorText)
	}

	return jsonResp.Request, nil
}

func (t *TwoCaptcha) getResult(ctx context.Context, settings *Settings, taskId string) (string, error) {
	type response struct {
		Status    int    `json:"status"`
		Request   string `json:"request"`
		ErrorText string `json:"error_text"`
	}

	body := &url.Values{}
	body.Set("key", t.apiKey)
	body.Set("action", "get")
	body.Set("json", "1")
	body.Set("id", taskId)

	fullURL := fmt.Sprintf("%v/res.php?%v", t.baseUrl, body.Encode())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := settings.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var jsonResp response
	if err := json.Unmarshal(respBody, &jsonResp); err != nil {
		return "", err
	}

	if jsonResp.Status == 0 {
		fmt.Println(jsonResp.Request)
		if jsonResp.ErrorText == "" {
			return "", nil
		}

		return "", fmt.Errorf("%v: %v", jsonResp.Request, jsonResp.ErrorText)
	}

	return jsonResp.Request, nil
}

var _ IProvider = (*TwoCaptcha)(nil)
