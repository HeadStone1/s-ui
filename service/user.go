package service

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/HeadStone1/s-ui/database"
	"github.com/HeadStone1/s-ui/database/model"
	"github.com/HeadStone1/s-ui/logger"
	"github.com/HeadStone1/s-ui/util/common"
)

type UserService struct {
}

type loginFailure struct {
	Count       int
	FirstFailed time.Time
	LockedUntil time.Time
}

var (
	loginFailureMu sync.Mutex
	loginFailures  = map[string]loginFailure{}
)

const (
	maxLoginFailures = 5
	loginFailureTTL  = 10 * time.Minute
	loginLockTTL     = 15 * time.Minute
)

const (
	TokenScopeRead  = "read"
	TokenScopeWrite = "write"
	TokenScopeAdmin = "admin"
)

func (s *UserService) GetFirstUser() (*model.User, error) {
	db := database.GetDB()

	user := &model.User{}
	err := db.Model(model.User{}).
		First(user).
		Error
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (s *UserService) UpdateFirstUser(username string, password string) error {
	if username == "" {
		return common.NewError("username can not be empty")
	} else if password == "" {
		return common.NewError("password can not be empty")
	}
	if username == "admin" && password == "admin" {
		return common.NewError("admin/admin is not allowed")
	}
	passwordHash, err := common.HashPassword(password)
	if err != nil {
		return err
	}
	db := database.GetDB()
	user := &model.User{}
	err = db.Model(model.User{}).First(user).Error
	if database.IsNotFound(err) {
		user.Username = username
		user.PasswordHash = passwordHash
		return db.Model(model.User{}).Create(user).Error
	} else if err != nil {
		return err
	}
	user.Username = username
	user.Password = ""
	user.PasswordHash = passwordHash
	return db.Save(user).Error
}

func (s *UserService) Login(username string, password string, remoteIP string) (string, error) {
	if isLoginLocked(username, remoteIP) {
		return "", common.NewError("too many failed login attempts, try again later")
	}
	user := s.CheckUser(username, password, remoteIP)
	if user == nil {
		recordLoginFailure(username, remoteIP)
		return "", common.NewError("wrong user or password! IP: ", remoteIP)
	}
	clearLoginFailure(username, remoteIP)
	return user.Username, nil
}

func loginFailureKey(username string, remoteIP string) string {
	return fmt.Sprintf("%s\x00%s", username, remoteIP)
}

func isLoginLocked(username string, remoteIP string) bool {
	loginFailureMu.Lock()
	defer loginFailureMu.Unlock()

	key := loginFailureKey(username, remoteIP)
	failure, ok := loginFailures[key]
	if !ok {
		return false
	}
	if !failure.LockedUntil.IsZero() && time.Now().Before(failure.LockedUntil) {
		return true
	}
	if time.Since(failure.FirstFailed) > loginFailureTTL {
		delete(loginFailures, key)
	}
	return false
}

func recordLoginFailure(username string, remoteIP string) {
	loginFailureMu.Lock()
	defer loginFailureMu.Unlock()

	now := time.Now()
	key := loginFailureKey(username, remoteIP)
	failure := loginFailures[key]
	if failure.FirstFailed.IsZero() || now.Sub(failure.FirstFailed) > loginFailureTTL {
		failure = loginFailure{FirstFailed: now}
	}
	failure.Count++
	if failure.Count >= maxLoginFailures {
		failure.LockedUntil = now.Add(loginLockTTL)
	}
	loginFailures[key] = failure
}

func clearLoginFailure(username string, remoteIP string) {
	loginFailureMu.Lock()
	defer loginFailureMu.Unlock()
	delete(loginFailures, loginFailureKey(username, remoteIP))
}

func (s *UserService) CheckUser(username string, password string, remoteIP string) *model.User {
	db := database.GetDB()

	user := &model.User{}
	err := db.Model(model.User{}).
		Where("username = ?", username).
		First(user).
		Error
	if database.IsNotFound(err) {
		return nil
	} else if err != nil {
		logger.Warning("check user err:", err, " IP: ", remoteIP)
		return nil
	}
	if !common.CheckPasswordHash(password, user.PasswordHash) {
		return nil
	}

	lastLoginTxt := time.Now().Format("2006-01-02 15:04:05") + " " + remoteIP
	err = db.Model(model.User{}).
		Where("id = ?", user.Id).
		Update("last_logins", &lastLoginTxt).Error
	if err != nil {
		logger.Warning("unable to log login data", err)
	}
	return user
}

func (s *UserService) CheckPassword(username string, password string) bool {
	db := database.GetDB()
	user := &model.User{}
	err := db.Model(model.User{}).Where("username = ?", username).First(user).Error
	if err != nil {
		return false
	}
	return common.CheckPasswordHash(password, user.PasswordHash)
}

func (s *UserService) GetUsers() (*[]model.User, error) {
	var users []model.User
	db := database.GetDB()
	err := db.Model(model.User{}).Select("id,username,last_logins").Scan(&users).Error
	if err != nil {
		return nil, err
	}
	return &users, nil
}

func (s *UserService) ChangePass(id string, oldPass string, newUser string, newPass string) error {
	if newUser == "" {
		return common.NewError("username can not be empty")
	} else if newPass == "" {
		return common.NewError("password can not be empty")
	}
	if newUser == "admin" && newPass == "admin" {
		return common.NewError("admin/admin is not allowed")
	}
	db := database.GetDB()
	user := &model.User{}
	err := db.Model(model.User{}).Where("id = ?", id).First(user).Error
	if err != nil || database.IsNotFound(err) {
		return err
	}
	if !common.CheckPasswordHash(oldPass, user.PasswordHash) {
		return common.NewError("wrong user or password")
	}
	passwordHash, err := common.HashPassword(newPass)
	if err != nil {
		return err
	}
	user.Username = newUser
	user.Password = ""
	user.PasswordHash = passwordHash
	return db.Save(user).Error
}

func (s *UserService) LoadTokens() ([]byte, error) {
	db := database.GetDB()
	var tokens []model.Tokens
	err := db.Model(model.Tokens{}).Preload("User").Where("expiry > ?", time.Now().Unix()).Find(&tokens).Error
	if err != nil {
		return nil, err
	}
	var result []map[string]interface{}
	for _, t := range tokens {
		result = append(result, map[string]interface{}{
			"tokenHash": t.TokenHash,
			"expiry":    t.Expiry,
			"username":  t.User.Username,
			"scope":     normalizeTokenScope(t.Scope),
		})
	}
	jsonResult, _ := json.MarshalIndent(result, "", "  ")
	return jsonResult, nil
}

func (s *UserService) GetUserTokens(username string) (*[]model.Tokens, error) {
	db := database.GetDB()
	var token []model.Tokens
	err := db.Model(model.Tokens{}).Select("id,desc,'****' as token,scope,expiry,user_id").Where("user_id = (select id from users where username = ?)", username).Find(&token).Error
	if err != nil && !database.IsNotFound(err) {
		println(err.Error())
		return nil, err
	}
	return &token, nil
}

func (s *UserService) AddToken(username string, expiry int64, desc string, scope string) (string, error) {
	if expiry <= 0 {
		return "", common.NewError("token expiry must be greater than zero")
	}
	scope = normalizeTokenScope(scope)
	if scope != TokenScopeRead && scope != TokenScopeWrite && scope != TokenScopeAdmin {
		return "", common.NewError("invalid token scope")
	}
	db := database.GetDB()
	var userId uint
	err := db.Model(model.User{}).Where("username = ?", username).Select("id").Scan(&userId).Error
	if err != nil {
		return "", err
	}
	expiry = expiry*86400 + time.Now().Unix()
	tokenValue := common.Random(32)
	token := &model.Tokens{
		TokenHash: common.HashToken(tokenValue),
		Scope:     scope,
		Desc:      desc,
		Expiry:    expiry,
		UserId:    userId,
	}
	err = db.Create(token).Error
	if err != nil {
		return "", err
	}
	return tokenValue, nil
}

func normalizeTokenScope(scope string) string {
	if scope == "" {
		return TokenScopeRead
	}
	switch scope {
	case TokenScopeWrite, TokenScopeAdmin:
		return scope
	case TokenScopeRead:
		return TokenScopeRead
	default:
		return scope
	}
}

func (s *UserService) DeleteToken(id string) error {
	db := database.GetDB()
	return db.Model(model.Tokens{}).Where("id = ?", id).Delete(&model.Tokens{}).Error
}
