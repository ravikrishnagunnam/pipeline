package auth

import (
	"net/http"

	"github.com/banzaicloud/pipeline/model"
	"github.com/casbin/casbin"
	gormadapter "github.com/casbin/gorm-adapter"
	"github.com/gin-gonic/gin"
)

// NewAuthorizer returns the MySQL based default authorizer
func NewAuthorizer() gin.HandlerFunc {
	a := gormadapter.NewAdapter("mysql", model.GetDataSource(""))
	e := casbin.NewEnforcer("authz_model.conf", a)
	if err := e.LoadPolicy(); err != nil {
		panic(err)
	}
	e.AddPolicy("bonifaido", "*", "*")
	e.SavePolicy()
	return newAuthorizer(e)
}

// NewAuthorizer returns the authorizer, uses a Casbin enforcer as input
func newAuthorizer(e *casbin.Enforcer) gin.HandlerFunc {
	return func(c *gin.Context) {
		a := &BasicAuthorizer{enforcer: e}

		if !a.CheckPermission(c.Request) {
			a.RequirePermission(c)
		}
	}
}

// BasicAuthorizer stores the casbin handler
type BasicAuthorizer struct {
	enforcer *casbin.Enforcer
}

// GetUserName gets the user name from the request.
// Currently, only HTTP basic authentication is supported
func (a *BasicAuthorizer) GetUserName(r *http.Request) string {
	user := GetCurrentUser(r)
	return user.Login
}

// CheckPermission checks the user/method/path combination from the request.
// Returns true (permission granted) or false (permission forbidden)
func (a *BasicAuthorizer) CheckPermission(r *http.Request) bool {
	user := a.GetUserName(r)
	method := r.Method
	path := r.URL.Path
	return a.enforcer.Enforce(user, path, method)
}

// RequirePermission returns the 403 Forbidden to the client
func (a *BasicAuthorizer) RequirePermission(c *gin.Context) {
	c.Writer.WriteHeader(403)
	c.Writer.Write([]byte("403 Forbidden\n"))
	c.Abort()
}
