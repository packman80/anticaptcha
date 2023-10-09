package anticaptcha

type ICaptchaResponse interface {
	// Solution will return the solution of the captcha as a string
	Solution() string
}

type CaptchaResponse struct {
	solution, taskId string
}

func (a *CaptchaResponse) Solution() string {
	return a.solution
}

var _ ICaptchaResponse = (*CaptchaResponse)(nil)
