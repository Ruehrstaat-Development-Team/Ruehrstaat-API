package util

import (
	"time"
)

type TimeMeasurer struct {
	name        string
	start       time.Time
	breakpoints map[string]time.Time
}

func MeasureTime(name string) *TimeMeasurer {
	return &TimeMeasurer{
		name:        name,
		start:       time.Now(),
		breakpoints: make(map[string]time.Time),
	}
}

func (t *TimeMeasurer) BeginBreakpoint(name string) {
	t.breakpoints[name] = time.Now()
}

func (t *TimeMeasurer) EndBreakpoint(name string) {
	if start, ok := t.breakpoints[name]; ok {
		log.Printf("Breakpoint %s took %s", name, time.Since(start))

		delete(t.breakpoints, name)
	}
}

func (t *TimeMeasurer) End() {
	log.Printf("TimeMeasurer %s took %s", t.name, time.Since(t.start))
}
