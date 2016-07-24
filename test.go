package main

import (
	"bufio"
	"fmt"
	"github.com/streamrail/uap-go/uaparser"
	"os"
	"time"
	netUtil "github.com/streamrail/common/util/net"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s [old|new|both]\n", os.Args[0])
		return
	}
	switch (os.Args[1]) {
		case "new":
			fmt.Printf("Running new version of uap...")
			uaParser, _ := uaparser.NewWithOptions("/etc/regexes.yaml", (uaparser.EOsLookUpMode | uaparser.EUserAgentLookUpMode), 100, 20, true)
			runTest(uaParser)
			return
		case "old":
			fmt.Printf("Running old version of uap...")
			uaParser, _ := uaparser.New("/etc/regexes.yaml")
			runTest(uaParser)
			return
		case "both":
			fmt.Printf("Running new version of uap...")
			uaParser, _ := uaparser.NewWithOptions("/etc/regexes.yaml", (uaparser.EOsLookUpMode | uaparser.EUserAgentLookUpMode), 100, 20, true)
			runTest(uaParser)
			fmt.Printf("Running old version of uap...")
			uaParser, _ = uaparser.New("/etc/regexes.yaml")
			runTest(uaParser)
			return
		default:
			fmt.Printf("Usage: %s [old|new|both]\n", os.Args[0])
			return
	}
}


func runTest(uaParser *uaparser.Parser) {
	file, err := os.Open("./uas")
	if err != nil {
		fmt.Printf("Failed to open ./wrappers file. Error: %s\n", err.Error())
		return
	}
	defer file.Close()
	line := 0
	totalLines := countLines()
	platforms := map[string]int{"mobile": 0, "desktop": 0}
	var totalTime time.Duration
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		str := scanner.Text()
		line++
		start := time.Now()
		if netUtil.IsMobileUA(str, uaParser.Parse(str)) {
			platforms["mobile"]++
		} else {
			platforms["desktop"]++
		}
		elapsed := time.Since(start)
		totalTime += elapsed
		fmt.Printf("\r\t\t\t\t%.2f%% completed", float64(line * 100)/float64(totalLines))
	}
	fmt.Printf("\nProcessed lines: %d. Test took %s\nResult: %+v\n", line, totalTime, platforms)
}

func countLines() (int) {
	file, _ := os.Open("./uas")
	fileScanner := bufio.NewScanner(file)
	defer file.Close()
	lineCount := 0
	for fileScanner.Scan() {
		lineCount++
	}
	return lineCount
}
