package auth

import (
	"fmt"
	"net/http"
	"time"

	"github.com/banzaicloud/pipeline/model"
	"github.com/casbin/casbin"
	"github.com/casbin/gorm-adapter"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

var enforcer *casbin.SyncedEnforcer

// NewAuthorizer returns the MySQL based default authorizer
func NewAuthorizer() gin.HandlerFunc {
	dbName := viper.GetString("database.dbname")
	a := gormadapter.NewAdapter("mysql", model.GetDataSource(dbName), true)
	enforcer = casbin.NewSyncedEnforcer("authz_model.conf", a)
	enforcer.StartAutoLoadPolicy(10 * time.Second)
	return newAuthorizer(enforcer)
}

// NewAuthorizer returns the authorizer, uses a Casbin enforcer as input
func newAuthorizer(e *casbin.SyncedEnforcer) gin.HandlerFunc {
	return func(c *gin.Context) {
		a := &BearerAuthorizer{enforcer: e}

		if !a.CheckPermission(c.Request) {
			a.RequirePermission(c)
		}
	}
}

// BearerAuthorizer stores the casbin handler
type BearerAuthorizer struct {
	enforcer *casbin.SyncedEnforcer
}

// GetUserName gets the user name from the request.
// Currently, only HTTP Bearer token authentication is supported
func (a *BearerAuthorizer) GetUserName(r *http.Request) string {
	user := GetCurrentUser(r)
	return user.Login
}

// CheckPermission checks the user/method/path combination from the request.
// Returns true (permission granted) or false (permission forbidden)
func (a *BearerAuthorizer) CheckPermission(r *http.Request) bool {
	user := a.GetUserName(r)
	method := r.Method
	path := r.URL.Path
	return a.enforcer.Enforce(user, path, method)
}

// RequirePermission returns the 403 Forbidden to the client
func (a *BearerAuthorizer) RequirePermission(c *gin.Context) {
	c.AbortWithStatus(http.StatusForbidden)
}

func addDefaultPolicies(username string, orgids ...uint) {
	enforcer.AddPolicy(username, "/api/v1/orgs", "*")
	enforcer.AddPolicy(username, "/api/v1/token", "*") // DEPRECATED
	enforcer.AddPolicy(username, "/api/v1/tokens", "*")
	for _, orgid := range orgids {
		enforcer.AddPolicy(username, fmt.Sprintf("/api/v1/orgs/%d", orgid), "*")
		enforcer.AddPolicy(username, fmt.Sprintf("/api/v1/orgs/%d/*", orgid), "*")
	}
	if err := enforcer.SavePolicy(); err != nil {
		panic(err)
	}
}
