package static

import "embed"

// EmbeddedFiles contains all static frontend assets compiled directly into the binary
//
//go:embed index.html app.js styles.css logo.jpg
var EmbeddedFiles embed.FS
