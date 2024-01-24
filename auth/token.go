package auth

type TokenPair struct {
	RefreshToken string `json:"-"`
	IdenityToken string `json:"token"`
	ExpiresIn    int64  `json:"expiresIn"`
}
