package scanner

type Options struct {
	Roots              []string
	IncludeNodeModules bool
	ScanCaches         bool
	ScanPython         bool
	ScanProcesses      bool
	MaxBytes           int64
}

type Finding struct {
	Severity string `json:"severity"`
	Type     string `json:"type"`
	File     string `json:"file"`
	Detail   string `json:"detail"`
}

type Counters struct {
	FilesSeen    int `json:"filesSeen"`
	FilesScanned int `json:"filesScanned"`
}

type Report struct {
	Vulnerable bool      `json:"vulnerable"`
	Critical   int       `json:"critical"`
	High       int       `json:"high"`
	Findings   []Finding `json:"findings"`
	Counters   Counters  `json:"counters"`
	Roots      []string  `json:"roots"`
	Guidance   string    `json:"guidance"`
}

const DefaultMaxBytes int64 = 8 * 1024 * 1024
