package auth

// TokenIssuer creates signed access and refresh tokens. JWT is the default
// implementation; use cases and the router depend on this interface, never on
// a concrete JWT type.
type TokenIssuer interface {
	// CreateToken mints an access token for the user.
	CreateToken(userID, email string) (string, error)
	// CreateRefreshToken mints a refresh token for the user.
	CreateRefreshToken(userID string) (string, error)
}

// PasswordHasher hashes and verifies passwords. bcrypt is the default
// implementation.
type PasswordHasher interface {
	// Hash returns an encoded hash of the plaintext password.
	Hash(password string) (string, error)
	// Verify reports whether a plaintext password matches an encoded hash.
	Verify(password, encoded string) bool
}

// bcryptHasher is the bcrypt-backed PasswordHasher.
type bcryptHasher struct{}

// NewPasswordHasher builds the bcrypt password hasher.
func NewPasswordHasher() PasswordHasher { return &bcryptHasher{} }

func (h *bcryptHasher) Hash(password string) (string, error) {
	return HashPassword(password)
}

func (h *bcryptHasher) Verify(password, encoded string) bool {
	return VerifyPassword(password, encoded)
}

// Compile-time checks that the concrete types satisfy the interfaces.
var (
	_ TokenIssuer    = (*JWTAuthenticator)(nil)
	_ PasswordHasher = (*bcryptHasher)(nil)
)
