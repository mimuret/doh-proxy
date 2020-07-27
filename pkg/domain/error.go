package domain

type ErrorCode string

const (
	ErrCodeBadRequest          ErrorCode = "BadRequest"
	ErrCodeResolvError                   = "ResolvError"
	ErrCodeInternalServerError           = "InternalServerError"
)

type Error struct {
	Err  error
	Code ErrorCode
}

func (e *Error) Unwrap() error { return e.Err }
func (e *Error) Error() string {
	return "doh-proxy(domain): " + e.Err.Error()
}
