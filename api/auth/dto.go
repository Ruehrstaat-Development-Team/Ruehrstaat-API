package auth

type registerBody struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Nickname string `json:"nickname"`
	CmdrName string `json:"cmdrName"`
}

type loginBody struct {
	Email    string  `json:"email" binding:"required"`
	Password string  `json:"password" binding:"required"`
	Otp      *string `json:"otp"`
}

type loginTotpBody struct {
	State string `json:"state" binding:"required"`
	Code  string `json:"code" binding:"required"`
}
