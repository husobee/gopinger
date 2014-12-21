package main

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

// TestMain - Test the main application entry
func TestMain(t *testing.T) {
	Convey("Main does nothing right now", t, func() {
		main()
		So(true, ShouldBeTrue)
	})
}
