module github.com/ochmunkh/tatar-kuber

go 1.22

// html/template-ийн XSS escaper CVE (GO-2026-4980/4982/6091) зассан stdlib-ийг
// build-д баталгаажуулна. Илүү шинэ Go суусан бол түүнийг ашиглана.
toolchain go1.25.13

require gopkg.in/yaml.v3 v3.0.1
