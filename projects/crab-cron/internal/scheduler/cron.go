package scheduler

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

type CronExpr struct {
	minute     cronField
	hour       cronField
	dayOfMonth cronField
	month      cronField
	dayOfWeek  cronField
}

func ParseCronExpr(expr string) (CronExpr, error) {
	parts := strings.Fields(strings.TrimSpace(expr))
	if len(parts) != 5 {
		return CronExpr{}, fmt.Errorf("invalid cron expression: expected 5 fields")
	}

	minute, err := parseCronField(parts[0], 0, 59)
	if err != nil {
		return CronExpr{}, fmt.Errorf("invalid minute field: %w", err)
	}
	hour, err := parseCronField(parts[1], 0, 23)
	if err != nil {
		return CronExpr{}, fmt.Errorf("invalid hour field: %w", err)
	}
	dayOfMonth, err := parseCronField(parts[2], 1, 31)
	if err != nil {
		return CronExpr{}, fmt.Errorf("invalid day-of-month field: %w", err)
	}
	month, err := parseCronField(parts[3], 1, 12)
	if err != nil {
		return CronExpr{}, fmt.Errorf("invalid month field: %w", err)
	}
	dayOfWeek, err := parseCronField(parts[4], 0, 6)
	if err != nil {
		return CronExpr{}, fmt.Errorf("invalid day-of-week field: %w", err)
	}

	return CronExpr{
		minute:     minute,
		hour:       hour,
		dayOfMonth: dayOfMonth,
		month:      month,
		dayOfWeek:  dayOfWeek,
	}, nil
}

func (e CronExpr) Matches(t time.Time) bool {
	if !e.minute.matches(t.Minute()) {
		return false
	}
	if !e.hour.matches(t.Hour()) {
		return false
	}
	if !e.month.matches(int(t.Month())) {
		return false
	}

	domMatch := e.dayOfMonth.matches(t.Day())
	dowMatch := e.dayOfWeek.matches(int(t.Weekday()))

	switch {
	case e.dayOfMonth.any && e.dayOfWeek.any:
		return domMatch && dowMatch
	case e.dayOfMonth.any:
		return dowMatch
	case e.dayOfWeek.any:
		return domMatch
	default:
		return domMatch || dowMatch
	}
}

type cronField struct {
	min     int
	max     int
	any     bool
	allowed []bool
}

func (f cronField) matches(value int) bool {
	if value < f.min || value > f.max {
		return false
	}
	return f.allowed[value-f.min]
}

func parseCronField(raw string, min int, max int) (cronField, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return cronField{}, fmt.Errorf("empty field")
	}

	field := cronField{
		min:     min,
		max:     max,
		allowed: make([]bool, max-min+1),
	}

	parts := strings.Split(raw, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return cronField{}, fmt.Errorf("empty list item")
		}

		switch {
		case part == "*":
			field.any = true
			for value := min; value <= max; value++ {
				field.allowed[value-min] = true
			}
		case strings.HasPrefix(part, "*/"):
			stepValue := strings.TrimPrefix(part, "*/")
			step, err := strconv.Atoi(stepValue)
			if err != nil {
				return cronField{}, fmt.Errorf("invalid interval %q", part)
			}
			if step <= 0 {
				return cronField{}, fmt.Errorf("interval must be > 0")
			}
			for value := min; value <= max; value += step {
				field.allowed[value-min] = true
			}
		case strings.Contains(part, "-"):
			bounds := strings.Split(part, "-")
			if len(bounds) != 2 {
				return cronField{}, fmt.Errorf("invalid range %q", part)
			}
			start, err := strconv.Atoi(strings.TrimSpace(bounds[0]))
			if err != nil {
				return cronField{}, fmt.Errorf("invalid range start %q", part)
			}
			end, err := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err != nil {
				return cronField{}, fmt.Errorf("invalid range end %q", part)
			}
			if start > end {
				return cronField{}, fmt.Errorf("range start must be <= range end")
			}
			if start < min || end > max {
				return cronField{}, fmt.Errorf("range %d-%d out of bounds (%d-%d)", start, end, min, max)
			}
			for value := start; value <= end; value++ {
				field.allowed[value-min] = true
			}
		default:
			value, err := strconv.Atoi(part)
			if err != nil {
				return cronField{}, fmt.Errorf("invalid value %q", part)
			}
			if value < min || value > max {
				return cronField{}, fmt.Errorf("value %d out of bounds (%d-%d)", value, min, max)
			}
			field.allowed[value-min] = true
		}
	}

	for _, allowed := range field.allowed {
		if allowed {
			return field, nil
		}
	}
	return cronField{}, fmt.Errorf("no values matched")
}
