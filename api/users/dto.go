package users

type editUserBody struct {
	Email    string `json:"email"`
	Nickname string `json:"nickname"`
	CmdrName string `json:"cmdrName"`

	IsBanned *bool `json:"isBanned"`
	IsAdmin  *bool `json:"isAdmin"`
}

type changeEmailBody struct {
	NewEmail string  `json:"newEmail" binding:"required"`
	Password string  `json:"password" binding:"required"`
	Otp      *string `json:"otp"`
}

type adminCreateUserBody struct {
	Email    string `json:"email" binding:"required"`
	Nickname string `json:"nickname" binding:"required"`
	CmdrName string `json:"cmdrName" binding:"required"`
	Password string `json:"password" binding:"required"`

	IsAdmin *bool `json:"isAdmin"`
}
