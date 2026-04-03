package auth

import (
	"net/http/httptest"
	"testing"

	"ruehrstaat-backend/errors"
	"ruehrstaat-backend/mailer"

	"github.com/gin-gonic/gin"
)

func TestSuppressCommittedMailFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("swallows committed mail delivery failure", func(t *testing.T) {
		ctx, _ := gin.CreateTestContext(httptest.NewRecorder())

		if got := suppressCommittedMailFailure(ctx, mailer.ErrFailedToSendEmail); got != nil {
			t.Fatalf("suppressCommittedMailFailure() = %v, want nil", got)
		}
		if len(ctx.Errors) != 1 {
			t.Fatalf("len(ctx.Errors) = %d, want 1", len(ctx.Errors))
		}
	})

	t.Run("keeps unrelated errors", func(t *testing.T) {
		ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
		err := errors.New(1, *errors.NewPackage("Test", "T"), 500, "T1", "test error")

		if got := suppressCommittedMailFailure(ctx, err); got != err {
			t.Fatalf("suppressCommittedMailFailure() = %v, want %v", got, err)
		}
		if len(ctx.Errors) != 0 {
			t.Fatalf("len(ctx.Errors) = %d, want 0", len(ctx.Errors))
		}
	})
}
