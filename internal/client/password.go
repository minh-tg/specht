package client

import "context"

// ChangePassword replaces the signed-in account's password. The server ends
// every other session and returns a fresh one for this caller.
func (c *Client) ChangePassword(current, next string) (*AuthResponse, error) {
	var resp AuthResponse
	err := c.do(context.Background(), "PUT", "/api/v1/me/password",
		map[string]string{"current_password": current, "new_password": next}, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}
