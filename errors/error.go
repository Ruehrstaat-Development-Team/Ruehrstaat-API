package errors

import (
	"fmt"

	"github.com/gin-gonic/gin"
)

type RstErrorPackage struct {
	Name  string
	Short string
}

func NewPackage(name string, short string) *RstErrorPackage {
	return &RstErrorPackage{name, short}
}

type RstError struct {
	code            int
	pkg             RstErrorPackage
	htmlCode        int
	nickname        string
	message         string
	InternalMessage string

	Stderr *error
}

func (e *RstError) Error() string {
	return fmt.Sprintf("%s: %s : %s", e.Nickname(), e.message, e.InternalMessage)
}

func (e *RstError) Message() string {
	return fmt.Sprintf("%s: %s", e.Nickname(), e.message)
}

func (e *RstError) Code() string {
	return fmt.Sprintf("%s%d", e.pkg.Short, e.code)
}

func (e *RstError) HtmlCode() int {
	return e.htmlCode
}

func (e *RstError) Nickname() string {
	if e.nickname == "" {
		return fmt.Sprintf("%s%d", e.pkg.Short, e.code)
	}
	return e.nickname
}

func New(code int, pkg RstErrorPackage, htmlCode int, nickname string, message string) *RstError {
	return &RstError{code, pkg, htmlCode, nickname, message, "", nil}
}

func NewWithInternalMessage(code int, pkg RstErrorPackage, htmlCode int, nickname string, message string, internalMessage string) *RstError {
	return &RstError{code, pkg, htmlCode, nickname, message, internalMessage, nil}
}

func NewFromError(err error) *RstError {
	return &RstError{9999, *NewPackage("Errors", "Err"), 500, "", err.Error(), err.Error(), &err}
}

func NewDBErrorFromError(err error) *RstError {
	return &RstError{9901, *NewPackage("Database", "DB"), 500, "", err.Error(), err.Error(), &err}
}

func NewAuthErrorFromError(err error) *RstError {
	return &RstError{9902, *NewPackage("Authentication", "Auth"), 500, "", err.Error(), err.Error(), &err}
}

// codes
// 1xxx - invalid something
// 2xxx - not found
// 3xxx - already done / exists
// 4xxx - forbidden
// 5xxx - server error

// 9xxx - other
// 9999 - unknown error

func ReturnWithError(c *gin.Context, err *RstError) {
	c.Error(err)
	c.JSON(err.HtmlCode(), gin.H{
		"error": err.Message(),
		"code":  err.Code(),
		"name":  err.Nickname(),
	})
}

func MiddlewareAbortWithError(c *gin.Context, err *RstError) {
	c.Error(err)
	c.JSON(err.HtmlCode(), gin.H{
		"error": err.Message(),
		"code":  err.Code(),
		"name":  err.Nickname(),
	})
	c.Abort()
}
