package scheduler

import (
	"context"
	"errors"
	"net"
	"net/http"
)

// ErrorClass 描述协调失败对重试策略的影响。
type ErrorClass string

const (
	ErrorTemporary          ErrorClass = "temporary"
	ErrorPermanentChallenge ErrorClass = "permanent_challenge"
	ErrorPermanent          ErrorClass = "permanent"
)

type temporaryMarker interface {
	Temporary() bool
}

type permanentChallengeMarker interface {
	PermanentChallenge() bool
}

type httpStatusCoder interface {
	HTTPStatusCode() int
}

type statusCoder interface {
	StatusCode() int
}

// TemporaryError 将实现方已确认可恢复的错误标记为临时错误。
type TemporaryError struct {
	Err error
}

func (e *TemporaryError) Error() string {
	if e == nil || e.Err == nil {
		return "临时错误"
	}
	return e.Err.Error()
}
func (e *TemporaryError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}
func (e *TemporaryError) Temporary() bool {
	return true
}

// PermanentChallengeError 表示 challenge 配置或校验的永久错误。
// worker 会保留有限次重试机会，并在达到 max attempts 后停止。
type PermanentChallengeError struct {
	Err error
}

func (e *PermanentChallengeError) Error() string {
	if e == nil || e.Err == nil {
		return "永久 challenge 错误"
	}
	return e.Err.Error()
}
func (e *PermanentChallengeError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}
func (e *PermanentChallengeError) PermanentChallenge() bool {
	return true
}

// HTTPError 为不依赖 HTTP 客户端实现的状态码错误。
type HTTPError struct {
	Code int
	Err  error
}

func (e *HTTPError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return http.StatusText(e.Code)
}

func (e *HTTPError) Unwrap() error       { return e.Err }
func (e *HTTPError) HTTPStatusCode() int { return e.Code }

// ClassifyError 将网络、DNS 和 HTTP 错误归入稳定的重试类别。
func ClassifyError(err error) ErrorClass {
	if err == nil {
		return ErrorPermanent
	}
	var challenge permanentChallengeMarker
	if errors.As(err, &challenge) && challenge.PermanentChallenge() {
		return ErrorPermanentChallenge
	}
	var markedTemporary temporaryMarker
	if errors.As(err, &markedTemporary) && markedTemporary.Temporary() {
		return ErrorTemporary
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrorTemporary
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.Timeout() {
		return ErrorTemporary
	}
	var netErr net.Error
	if errors.As(err, &netErr) && (netErr.Timeout() || netErr.Temporary()) {
		return ErrorTemporary
	}
	var httpErr httpStatusCoder
	if errors.As(err, &httpErr) && temporaryHTTPStatus(httpErr.HTTPStatusCode()) {
		return ErrorTemporary
	}
	var statusErr statusCoder
	if errors.As(err, &statusErr) && temporaryHTTPStatus(statusErr.StatusCode()) {
		return ErrorTemporary
	}
	return ErrorPermanent
}

func temporaryHTTPStatus(code int) bool {
	return code == http.StatusTooManyRequests || code >= 500 && code <= 599
}
