package kcptun

// ModeParams contains the KCP parameters for different transmission modes.
type ModeParams struct {
	NoDelay      int
	Interval     int
	Resend       int
	NoCongestion int
}

// PredefinedModes maps mode names to their KCP parameters.
// Using a map simplifies mode selection and makes adding new modes easier.
var PredefinedModes = map[string]ModeParams{
	"normal": {0, 40, 2, 1},
	"fast":   {0, 30, 2, 1},
	"fast2":  {1, 20, 2, 1},
	"fast3":  {1, 10, 2, 1},
}
