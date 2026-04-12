package main

// This package is named 'envenc' to match the binary name that will be
// installed when users run: go install github.com/dracory/envenc/envenc@latest
//
// In Go, the 'go install' command uses the directory name as the binary name.
// By naming this directory 'envenc', the installed binary will be called
// 'envenc' (or 'envenc.exe' on Windows) rather than a generic name like 'cmd'.
//
// This follows the standard Go convention for CLI tools where the main package
// directory should be named after the desired executable name.
