package uaparser

import (
	"bytes"
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"sort"
	"math"
)

type Parser struct {
	UserAgentPatterns []UserAgentPattern
	UserAgentMisses   int
	OsPatterns        []OsPattern
	OsMisses          int
	DevicePatterns    []DevicePattern
	DeviceMisses      int
	Mode              int
}

type Client struct {
	UserAgent *UserAgent
	Os        *Os
	Device    *Device
}

const (
	EOsLookUpMode		= 1	/* 00000001 */
	EUserAgentLookUpMode	= 2	/* 00000010 */
	EDeviceLookUpMode	= 4	/* 00000100 */
	cMinMissesTreshold	= 100000
	CDefaultMissesTreshold	= 500000
	CDefaultMatchIdxNotOk	= 20
)

var (
	exportedNameRegex = regexp.MustCompile("[0-9A-Za-z]+")
	missesTreshold    = 500000
	matchIdxNotOk   = 20
)

func GetExportedName(src string) string {
	byteSrc := []byte(src)
	chunks := exportedNameRegex.FindAll(byteSrc, -1)
	for idx, val := range chunks {
		chunks[idx] = bytes.Title(val)
	}
	return string(bytes.Join(chunks, nil))
}

func ToStruct(interfaceArr []map[string]string, typeInterface interface{}, returnVal *[]interface{}) {
	structArr := make([]interface{}, 0)
	for _, interfaceMap := range interfaceArr {
		structValPtr := reflect.New(reflect.TypeOf(typeInterface))
		structVal := structValPtr.Elem()
		for key, value := range interfaceMap {
			structVal.FieldByName(GetExportedName(key)).SetString(value)
		}
		structArr = append(structArr, structVal.Interface())
	}
	*returnVal = structArr
}

func NewWithOptions(regexFile string, mode, treshold, topCnt int) (*Parser, error) {
	parser := new(Parser)

	data, err := ioutil.ReadFile(regexFile)
	if nil != err {
		return nil, err
	}
	if topCnt >= 0 {
		matchIdxNotOk = topCnt
	}

	if treshold > cMinMissesTreshold {
		missesTreshold = treshold
	}
	parser.Mode = mode
	return parser.newFromBytes(data)
}

func New(regexFile string) (*Parser, error) {
	parser := new(Parser)

	data, err := ioutil.ReadFile(regexFile)
	if nil != err {
		return nil, err
	}
	matchIdxNotOk = CDefaultMatchIdxNotOk
	missesTreshold = CDefaultMissesTreshold
	parser.Mode = (EOsLookUpMode | EUserAgentLookUpMode | EDeviceLookUpMode)
	return parser.newFromBytes(data)
}

func NewFromBytes(regexBytes []byte) (*Parser, error) {
	parser := new(Parser)

	return parser.newFromBytes(regexBytes)
}

func (parser *Parser) newFromBytes(data []byte) (*Parser, error) {
	m := make(map[string][]map[string]string)
	err := yaml.Unmarshal(data, &m)
	if err != nil {
		return nil, err
	}

	var wg sync.WaitGroup

	uaPatternType := new(UserAgentPattern)
	var uaInterfaces []interface{}
	var uaPatterns []UserAgentPattern

	wg.Add(1)
	go func() {
		ToStruct(m["user_agent_parsers"], *uaPatternType, &uaInterfaces)
		uaPatterns = make([]UserAgentPattern, len(uaInterfaces))
		for i, inter := range uaInterfaces {
			uaPatterns[i] = inter.(UserAgentPattern)
			uaPatterns[i].Regexp = regexp.MustCompile(uaPatterns[i].Regex)
			uaPatterns[i].MatchesCount = 0
		}
		wg.Done()
	}()

	osPatternType := new(OsPattern)
	var osInterfaces []interface{}
	var osPatterns []OsPattern

	wg.Add(1)
	go func() {
		ToStruct(m["os_parsers"], *osPatternType, &osInterfaces)
		osPatterns = make([]OsPattern, len(osInterfaces))
		for i, inter := range osInterfaces {
			osPatterns[i] = inter.(OsPattern)
			osPatterns[i].Regexp = regexp.MustCompile(osPatterns[i].Regex)
		}
		wg.Done()
	}()

	dvcPatternType := new(DevicePattern)
	var dvcInterfaces []interface{}
	var dvcPatterns []DevicePattern

	wg.Add(1)
	go func() {
		ToStruct(m["device_parsers"], *dvcPatternType, &dvcInterfaces)
		dvcPatterns = make([]DevicePattern, len(dvcInterfaces))
		for i, inter := range dvcInterfaces {
			dvcPatterns[i] = inter.(DevicePattern)
			flags := ""
			if strings.Contains(dvcPatterns[i].RegexFlag, "i") {
				flags = "(?i)"
			}
			regexString := fmt.Sprintf("%s%s", flags, dvcPatterns[i].Regex)
			dvcPatterns[i].Regexp = regexp.MustCompile(regexString)
			dvcPatterns[i].MatchesCount = 0
		}
		wg.Done()
	}()

	wg.Wait()

	parser.UserAgentPatterns = uaPatterns
	parser.OsPatterns = osPatterns
	parser.DevicePatterns = dvcPatterns

	return parser, nil
}

func (parser *Parser) ParseUserAgent(line string) *UserAgent {
	ua := new(UserAgent)
	foundIdx := math.MaxInt32
	found := false
	for i, uaPattern := range parser.UserAgentPatterns {
		uaPattern.Match(line, ua)
		if len(ua.Family) > 0 {
			found = true
			foundIdx = i
			parser.UserAgentPatterns[i].MatchesCount++
			break
		}
	}
	if !found {
		foundIdx = -1
		ua.Family = "Other"
	}
	if(foundIdx > matchIdxNotOk) {
		parser.UserAgentMisses++
	}
	return ua
}

func (parser *Parser) ParseOs(line string) *Os {
	os := new(Os)
	foundIdx := math.MaxInt32
	found := false
	for i, osPattern := range parser.OsPatterns {
		osPattern.Match(line, os)
		if len(os.Family) > 0 {
			found = true
			foundIdx = i
			parser.OsPatterns[i].MatchesCount++
			break
		}
	}
	if !found {
		foundIdx = -1
		os.Family = "Other"
	}
	if(foundIdx > matchIdxNotOk) {
		parser.OsMisses++
	}
	return os
}

func (parser *Parser) ParseDevice(line string) *Device {
	dvc := new(Device)
	foundIdx := math.MaxInt32
	found := false
	for i, dvcPattern := range parser.DevicePatterns {
		dvcPattern.Match(line, dvc)
		if len(dvc.Family) > 0 {
			found = true
			foundIdx = i
			parser.DevicePatterns[i].MatchesCount++
			break
		}
	}
	if !found {
		foundIdx = -1
		dvc.Family = "Other"
	}
	if(foundIdx > matchIdxNotOk) {
		parser.DeviceMisses++
	}
	return dvc
}

func (parser *Parser) Parse(line string) *Client {
	cli := new(Client)
	if EUserAgentLookUpMode & parser.Mode == EUserAgentLookUpMode {
		cli.UserAgent = parser.ParseUserAgent(line)
	}
	if EOsLookUpMode & parser.Mode == EOsLookUpMode {
		cli.Os = parser.ParseOs(line)
	}
	if EDeviceLookUpMode & parser.Mode == EDeviceLookUpMode {
		cli.Device = parser.ParseDevice(line)
	}
	checkAndSort(parser)
	return cli
}

func checkAndSort(parser *Parser) {
	if(parser.UserAgentMisses >= missesTreshold) {
		parser.UserAgentMisses = 0
		sort.Sort(UserAgentPatternSorter(parser.UserAgentPatterns));
	}
	if(parser.OsMisses >= missesTreshold) {
		parser.OsMisses = 0
		sort.Sort(OsPatternSorter(parser.OsPatterns));
	}
	if(parser.DeviceMisses >= missesTreshold) {
		parser.DeviceMisses = 0
		sort.Sort(DevicePatternSorter(parser.DevicePatterns));
	}
}

func singleMatchReplacement(replacement string, matches []string, idx int) string {
	token := "$" + strconv.Itoa(idx)
	if strings.Contains(replacement, token) {
		return strings.Replace(replacement, token, matches[idx], -1)
	}
	return replacement
}

// allMatchesReplacement replaces all tokens in format $<digit> (like $1 or $12) with values
// at corresponding indexes (NOT POSITIONS, so $1 will be replaced with v[1], NOT v[0]) in the provided array.
// If array doesn't have value at the index (when array length is less than the value), it remains unchanged in the string
func allMatchesReplacement(pattern string, matches []string) string {
	var output bytes.Buffer
	readingToken := false
	var readToken bytes.Buffer
	writeTokenValue := func() {
		if !readingToken {
			return
		}
		if readToken.Len() == 0 {
			output.WriteRune('$')
			return
		}
		idx, err := strconv.Atoi(readToken.String())
		// index is out of range when value is too big for int or when it's zero (or less) or greater than array length
		indexOutOfRange := (err != nil && err.(*strconv.NumError).Err != strconv.ErrRange) || idx <= 0 || idx >= len(matches)
		if indexOutOfRange {
			output.WriteRune('$')
			output.Write(readToken.Bytes())
			readToken.Reset()
			return
		}
		if err != nil {
			// should never happen
			panic(err)
		}
		output.WriteString(matches[idx])
		readToken.Reset()
	}
	for _, r := range pattern {
		if !readingToken && r == '$' {
			readingToken = true
			continue
		}
		if !readingToken {
			output.WriteRune(r)
			continue
		}
		if unicode.IsDigit(r) {
			readToken.WriteRune(r)
			continue
		}
		writeTokenValue()
		readingToken = (r == '$')
		if !readingToken {
			output.WriteRune(r)
		}
	}
	writeTokenValue()
	return output.String()
}
