//go:build race

package main

// raceDetector reports whether the tests were built with the race
// detector, under which the stand-in hosts' signature checks are an order
// of magnitude slower.
const raceDetector = true
