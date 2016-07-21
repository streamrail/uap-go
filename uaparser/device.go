package uaparser

import (
	"regexp"
	"strings"
)

type Device struct {
	Family string
}

type DevicePattern struct {
	Regexp            *regexp.Regexp
	Regex             string
	RegexFlag         string
	BrandReplacement  string
	DeviceReplacement string
	ModelReplacement  string
	MatchesCount      int
}

type DevicePatternSorter []DevicePattern
func (a DevicePatternSorter) Len() int           { return len(a) }
func (a DevicePatternSorter) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a DevicePatternSorter) Less(i, j int) bool { return a[i].MatchesCount > a[j].MatchesCount }

func (dvcPattern *DevicePattern) Match(line string, dvc *Device) {
	matches := dvcPattern.Regexp.FindStringSubmatch(line)
	if len(matches) == 0 {
		return
	}
	groupCount := dvcPattern.Regexp.NumSubexp()

	if len(dvcPattern.DeviceReplacement) > 0 {
		dvc.Family = allMatchesReplacement(dvcPattern.DeviceReplacement, matches)
	} else if groupCount >= 1 {
		dvc.Family = matches[1]
	}
	dvc.Family = strings.TrimSpace(dvc.Family)
}

func (dvc *Device) ToString() string {
	return dvc.Family
}
