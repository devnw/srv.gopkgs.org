package main

import (
	"fmt"
	"net/http"
)

func Err(r *http.Request, err error, status int, msg string) error {
	return &Error{
		Endpoint: r.URL.Path,
		Method:   r.Method,
		Code:     status,
		Inner:    err,
		Message:  msg,
	}
}

type Error struct {
	Endpoint string `json:"endpoint"`
	Method   string `json:"method"`
	Message  string `json:"message"`
	Inner    error  `json:"inner"`
	Code     int    `json:"-"`
}

func (e *Error) String() string {
	msg := e.Message
	if e.Inner != nil {
		msg = fmt.Sprintf("%s: %s", e.Message, e.Inner.Error())
	}

	return fmt.Sprintf("%s %s: %s", e.Endpoint, e.Method, msg)
}

func (e *Error) Error() string {
	return e.String()
}
