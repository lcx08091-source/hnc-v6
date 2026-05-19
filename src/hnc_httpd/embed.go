package main

import _ "embed"

//go:embed web/app.html
var indexHTML []byte

//go:embed web/app.js
var appJS []byte

//go:embed web/style.css
var styleCSS []byte

//go:embed web/pair.html
var pairHTML []byte
