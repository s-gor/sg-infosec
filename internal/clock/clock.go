package clock

import "time"

type Clock interface {
	Now() time.Time
}

type Real struct{}

func (Real) Now() time.Time { return time.Now().UTC() }

type Fake struct {
	Current time.Time
}

func (f *Fake) Now() time.Time              { return f.Current }
func (f *Fake) Set(value time.Time)         { f.Current = value }
func (f *Fake) Advance(delta time.Duration) { f.Current = f.Current.Add(delta) }
