package client

// DefaultAPIURL is the server the command-line tools talk to when no URL is
// configured.
const DefaultAPIURL = "http://localhost:8080"

// EnvAPIURL returns the Specht base URL from API_URL, or from its alias
// SPECHT_API_URL when API_URL is empty. The order matches the adapter.
func EnvAPIURL(getenv func(string) string) string {
	return firstEnv(getenv, "API_URL", "SPECHT_API_URL")
}

// EnvAPIKey returns the API key from API_KEY, or from its alias
// SPECHT_API_KEY when API_KEY is empty. The order matches the adapter.
func EnvAPIKey(getenv func(string) string) string {
	return firstEnv(getenv, "API_KEY", "SPECHT_API_KEY")
}

func firstEnv(getenv func(string) string, names ...string) string {
	for _, name := range names {
		if v := getenv(name); v != "" {
			return v
		}
	}
	return ""
}
