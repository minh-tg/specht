package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRepoRef(t *testing.T) {
	tests := []struct {
		input   string
		want    RepoRef
		wantErr bool
	}{
		{
			input: "github://minhx/specht",
			want:  RepoRef{Provider: "github", Owner: "minhx", Repo: "specht"},
		},
		{
			input: "gitlab://mygroup/subgroup/myrepo",
			want:  RepoRef{Provider: "gitlab", Owner: "mygroup", Repo: "subgroup/myrepo"},
		},
		{
			input: "",
			want:  RepoRef{},
		},
		{
			input:   "github://minhx",
			wantErr: true,
		},
		{
			input:   "github:minhx/specht",
			wantErr: true, // missing://
		},
		{
			input:   ":/minhx/repo",
			wantErr: true, // empty provider
		},
		{
			input:   "github:///repo",
			wantErr: true, // empty owner
		},
		{
			input:   "github://minhx/",
			wantErr: true, // empty repo
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseRepoRef(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRepoRefString(t *testing.T) {
	r := RepoRef{Provider: "github", Owner: "minhx", Repo: "specht"}
	assert.Equal(t, "github://minhx/specht", r.String())

	empty := RepoRef{}
	assert.Equal(t, "", empty.String())
}

func TestRepoRefFullName(t *testing.T) {
	r := RepoRef{Provider: "gitlab", Owner: "myorg", Repo: "myproject"}
	assert.Equal(t, "myorg/myproject", r.FullName())
}

func TestParseRepoRef_RoundTrip(t *testing.T) {
	original := "github://minhx/specht"
	ref, err := ParseRepoRef(original)
	require.NoError(t, err)
	assert.Equal(t, original, ref.String())
}
