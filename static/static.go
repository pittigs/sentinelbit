package static

import "embed"

// EmbeddedFiles contains all static frontend assets compiled directly into the binary
//
//go:embed index.html app.js styles.css logo.jpg icon16.png icon48.png icon128.png manifest.webmanifest sw.js
var EmbeddedFiles embed.FS
