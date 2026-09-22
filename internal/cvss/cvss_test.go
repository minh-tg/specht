package cvss_test

import (
	"testing"

	"github.com/minh-tg/specht/internal/cvss"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCalculate_V3_Unknown(t *testing.T) {
	_, err := cvss.Calculate("")
	require.Error(t, err)
}

func TestCalculate_V3_Malformed(t *testing.T) {
	_, err := cvss.Calculate("CVSS:3.1")
	require.Error(t, err)
}

func TestCalculate_V3_UnknownVersion(t *testing.T) {
	_, err := cvss.Calculate("CVSS:9.9/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	require.Error(t, err)
}

func TestCalculate_V3_NVDExamples(t *testing.T) {
	tests := []struct {
		vector string
		want   float64
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", 7.5},
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", 3.7},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L", 7.3},
		{"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N", 2.7},
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
	}

	for _, tt := range tests {
		t.Run(tt.vector, func(t *testing.T) {
			got, err := cvss.Calculate(tt.vector)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCalculate_V3_ScopeChanged(t *testing.T) {
	tests := []struct {
		vector string
		want   float64
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1},
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:L", 6.5},
		{"CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H", 7.6},
	}

	for _, tt := range tests {
		t.Run(tt.vector, func(t *testing.T) {
			got, err := cvss.Calculate(tt.vector)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCalculate_V4_Examples(t *testing.T) {
	tests := []struct {
		vector string
		want   float64
	}{
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N", 9.3},
		{"CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", 6.3},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N", 8.7},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N", 5.3},
		{"CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.vector, func(t *testing.T) {
			got, err := cvss.Calculate(tt.vector)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCalculate_V4_RejectsV3MetricKeys(t *testing.T) {
	_, err := cvss.Calculate("CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	require.Error(t, err)
}

func TestCalculate_V2_Examples(t *testing.T) {
	tests := []struct {
		vector string
		want   float64
	}{
		{"CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:N/A:N", 5.0},
		{"CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", 7.5},
		{"CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C", 10.0},
		{"CVSS:2.0/AV:N/AC:H/Au:N/C:N/I:N/A:N", 0.0},
		{"CVSS:2.0/AV:N/AC:L/Au:S/C:C/I:C/A:C", 9.0},
		{"CVSS:2.0/AV:L/AC:H/Au:M/C:C/I:C/A:C", 5.9},
		{"CVSS:2.0/AV:A/AC:L/Au:N/C:C/I:C/A:C", 8.3},
	}

	for _, tt := range tests {
		t.Run(tt.vector, func(t *testing.T) {
			got, err := cvss.Calculate(tt.vector)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
