package main

import _ "embed"

// v5.33: 只剩配对页。旧版远程界面(web/app.html / app.js / style.css)已删,
// 所有入口都用磁盘上的 webroot/index.html(见 server.go serveIndex)。
//
//go:embed web/pair.html
var pairHTML []byte
