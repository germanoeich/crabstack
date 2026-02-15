package scheduler

import (
	"testing"
	"time"
)

func TestParseCronExprValid(t *testing.T) {
	t.Parallel()

	cases := []string{
		"* * * * *",
		"*/5 * * * *",
		"0 12 * * 1-5",
		"15 10 1,15 * *",
		"0,30 9-17 * 1,6,12 0,6",
	}

	for _, expr := range cases {
		expr := expr
		t.Run(expr, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseCronExpr(expr); err != nil {
				t.Fatalf("expected valid expression, got error: %v", err)
			}
		})
	}
}

func TestCronExprMatches(t *testing.T) {
	t.Parallel()

	expr, err := ParseCronExpr("*/15 9-17 * * 1-5")
	if err != nil {
		t.Fatalf("parse expression: %v", err)
	}

	cases := []struct {
		name  string
		time  time.Time
		match bool
	}{
		{
			name:  "weekday in range",
			time:  time.Date(2026, time.February, 16, 9, 30, 0, 0, time.UTC),
			match: true,
		},
		{
			name:  "minute not matching interval",
			time:  time.Date(2026, time.February, 16, 9, 31, 0, 0, time.UTC),
			match: false,
		},
		{
			name:  "hour out of range",
			time:  time.Date(2026, time.February, 16, 8, 30, 0, 0, time.UTC),
			match: false,
		},
		{
			name:  "weekend excluded",
			time:  time.Date(2026, time.February, 14, 9, 30, 0, 0, time.UTC),
			match: false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := expr.Matches(tc.time); got != tc.match {
				t.Fatalf("Matches(%s) got=%v want=%v", tc.time.Format(time.RFC3339), got, tc.match)
			}
		})
	}
}

func TestParseCronExprInvalid(t *testing.T) {
	t.Parallel()

	cases := []string{
		"",
		"* * * *",
		"* * * * * *",
		"60 * * * *",
		"* 24 * * *",
		"* * 0 * *",
		"* * * 13 *",
		"* * * * 7",
		"*/0 * * * *",
		"5-1 * * * *",
		"a * * * *",
		"1,,2 * * * *",
	}

	for _, expr := range cases {
		expr := expr
		t.Run(expr, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseCronExpr(expr); err == nil {
				t.Fatalf("expected parse error for %q", expr)
			}
		})
	}
}

func TestCronExprIntervalsRangesAndLists(t *testing.T) {
	t.Parallel()

	expr, err := ParseCronExpr("0,15,30,45 10-12 * * 1,2,3")
	if err != nil {
		t.Fatalf("parse expression: %v", err)
	}

	if !expr.Matches(time.Date(2026, time.February, 17, 11, 15, 0, 0, time.UTC)) {
		t.Fatalf("expected matching Tuesday timestamp")
	}
	if expr.Matches(time.Date(2026, time.February, 19, 11, 15, 0, 0, time.UTC)) {
		t.Fatalf("expected Thursday timestamp not to match")
	}
	if expr.Matches(time.Date(2026, time.February, 17, 9, 15, 0, 0, time.UTC)) {
		t.Fatalf("expected hour out of range not to match")
	}
	if expr.Matches(time.Date(2026, time.February, 17, 11, 10, 0, 0, time.UTC)) {
		t.Fatalf("expected minute not in list not to match")
	}
}

func TestCronExprDayOfMonthDayOfWeekOR(t *testing.T) {
	t.Parallel()

	expr, err := ParseCronExpr("0 8 15 * 1")
	if err != nil {
		t.Fatalf("parse expression: %v", err)
	}

	var dayOfMonthOnly time.Time
	var dayOfWeekOnly time.Time
	var neither time.Time

	for day := 1; day <= 28; day++ {
		candidate := time.Date(2026, time.January, day, 8, 0, 0, 0, time.UTC)
		isDom := candidate.Day() == 15
		isDow := candidate.Weekday() == time.Monday

		switch {
		case isDom && !isDow && dayOfMonthOnly.IsZero():
			dayOfMonthOnly = candidate
		case !isDom && isDow && dayOfWeekOnly.IsZero():
			dayOfWeekOnly = candidate
		case !isDom && !isDow && neither.IsZero():
			neither = candidate
		}
	}

	if dayOfMonthOnly.IsZero() || dayOfWeekOnly.IsZero() || neither.IsZero() {
		t.Fatalf("failed to build test fixtures")
	}

	if !expr.Matches(dayOfMonthOnly) {
		t.Fatalf("expected day-of-month match")
	}
	if !expr.Matches(dayOfWeekOnly) {
		t.Fatalf("expected day-of-week match")
	}
	if expr.Matches(neither) {
		t.Fatalf("expected neither day-of-month nor day-of-week to fail")
	}
}
