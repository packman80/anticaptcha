package anticaptcha

type ICaptchaResponse interface {
	// Solution will return the solution of the captcha as a string
	Solution() (string, string)
}

type CaptchaResponse struct {
	solution, taskId string
}

func (a *CaptchaResponse) Solution() (solution, taskId string) {
	return a.solution, a.taskId
}

var _ ICaptchaResponse = (*CaptchaResponse)(nil)
