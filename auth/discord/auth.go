package discord

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"os"
	"ruehrstaat-backend/logging"
	"ruehrstaat-backend/util"

	jsoniter "github.com/json-iterator/go"
	"github.com/ravener/discord-oauth2"
	"golang.org/x/oauth2"
)

var LinkingConf *oauth2.Config
var LoginConf *oauth2.Config

var log = logging.Logger{Package: "discord"}

func Initialize() {
	LinkingConf = &oauth2.Config{
		RedirectURL:  os.Getenv("BACKEND_URL") + "/v1/users/link/discord/callback",
		ClientID:     os.Getenv("DISCORD_CLIENT_ID"),
		ClientSecret: os.Getenv("DISCORD_CLIENT_SECRET"),
		Scopes:       []string{discord.ScopeIdentify},
		Endpoint:     discord.Endpoint,
	}
	LoginConf = &oauth2.Config{
		RedirectURL:  os.Getenv("BACKEND_URL") + "/v1/auth/discord/callback",
		ClientID:     os.Getenv("DISCORD_CLIENT_ID"),
		ClientSecret: os.Getenv("DISCORD_CLIENT_SECRET"),
		Scopes:       []string{discord.ScopeIdentify},
		Endpoint:     discord.Endpoint,
	}
}

func GenerateCodeVerifier() (string, error) {
	return util.GenerateRandomString(128)
}

func GetOAuthUrl(conf *oauth2.Config, state string, codeVerifier string) string {
	sha2 := sha256.New()
	io.WriteString(sha2, codeVerifier)
	codeChallenge := base64.RawURLEncoding.EncodeToString(sha2.Sum(nil))
	return conf.AuthCodeURL(state, oauth2.SetAuthURLParam("code_challenge", codeChallenge), oauth2.SetAuthURLParam("code_challenge_method", "S256"))
}

func RetrieveOAuthUser(conf *oauth2.Config, state string, code string, codeVerifier string) (bool, *DiscordUser) {
	token, err := conf.Exchange(context.Background(), code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	if err != nil {
		log.Printf(err.Error())
		return false, nil
	}

	res, err := conf.Client(context.Background(), token).Get("https://discord.com/api/users/@me")
	if err != nil {
		log.Printf(err.Error())
		return false, nil
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Printf(err.Error())
		return false, nil
	}

	discordUser := &DiscordUser{}

	if err := jsoniter.Unmarshal(body, &discordUser); err != nil {
		log.Printf(err.Error())
		return false, nil
	}

	return true, discordUser
}
