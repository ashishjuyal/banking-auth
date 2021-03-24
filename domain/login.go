package domain

import (
	"database/sql"
	"github.com/dgrijalva/jwt-go"
	"strings"
	"time"
)

type Login struct {
	Username   string         `db:"username"`
	CustomerId sql.NullString `db:"customer_id"`
	Accounts   sql.NullString `db:"account_numbers"`
	Role       string         `db:"role"`
}

func (l Login) ClaimsForAccessToken() Claims {
	if l.Accounts.Valid && l.CustomerId.Valid {
		return l.claimsForUser()
	} else {
		return l.claimsForAdmin()
	}
}

func (l Login) claimsForUser() Claims {
	accounts := strings.Split(l.Accounts.String, ",")
	return Claims{
		CustomerId: l.CustomerId.String,
		Accounts:   accounts,
		Username:   l.Username,
		Role:       l.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(TOKEN_DURATION).Unix(),
		},
	}
}

func (l Login) claimsForAdmin() Claims {
	return Claims{
		Username: l.Username,
		Role:     l.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(TOKEN_DURATION).Unix(),
		},
	}
}
