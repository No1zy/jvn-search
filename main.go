package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"github.com/No1zy/jvn_search/db"
	"github.com/No1zy/jvn_search/jvn"
	"github.com/No1zy/jvn_search/parser"
	"github.com/No1zy/jvn_search/util"
	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/transform"
	"log"
	"os"
	"strings"
	"unicode/utf8"
)

func main() {
	var (
		exportFile string
	)
	fetch := flag.NewFlagSet("fetch", flag.ExitOnError)
	search := flag.NewFlagSet("search", flag.ExitOnError)
	search.StringVar(&exportFile, "o", "", "export CSV format")

	switch os.Args[1] {
	case "search":
		search.Parse(os.Args[3:])
	case "fetch":
		fetch.Parse(os.Args[2:])
	default:
		parseError()
	}
	if search.Parsed() {
		sqlite := db.New()
		defer sqlite.Close()
		if os.Args[2] == "" {
			fmt.Fprintf(os.Stderr, "require search keyword.\n")
			os.Exit(1)
		}
		result := db.GetProduct(sqlite, os.Args[2])
		if len(exportFile) > 0 {
			f, err := os.Create(exportFile)
			writer := csv.NewWriter(transform.NewWriter(f, japanese.ShiftJIS.NewEncoder()))
			if err != nil {
				log.Fatal(err)
			}

			//取得結果をcsvに1行ずつ書き出す
			for _, value := range result {
				record := csvconv(&value)
				if err := writer.Write(record); err != nil {
					log.Fatal(err)
				}
				writer.Flush()
			}
		} else {
			for _, value := range result {
				fmt.Println(value.Cve + "\t| " + value.Cvss + "\t| " + value.Overview)
			}
		}
	}

	if fetch.Parsed() {
		config, err := parser.CreateConfig()
		if err != nil {
			log.Fatal(err)
		}

		for _, product := range config.Product {
			param := jvn.RequestParams{
				product,
				"1",
				"50",
			}
			overviews := jvn.FetchJvn(param)

			reqChan := make(chan parser.Item, len(overviews))
			resChan := make(chan db.QueryObject, len(overviews))

			defer close(reqChan)
			defer close(resChan)

			go func() {
				for _, overview := range overviews {
					reqChan <- overview
				}
			}()

			worker := util.GenWorkers(len(overviews))

			for range overviews {
				worker <- func() {
					select {
					case overview := <-reqChan:
						detail := jvn.FetchJvnDetail(overview.Identifier)
						resChan <- createQueryObjct(param.Keyword, overview, detail)

					}
				}
			}
			sqlite := db.New()

			defer sqlite.Close()

			for range overviews {
				select {
				case obj := <-resChan:
					db.InsertJVN(sqlite, &obj)
				}
			}
		}
		fmt.Println("Finished!!")
	}
}

func usage() {
	fmt.Printf("%s <command> ... \n\n", os.Args[0])
	fmt.Println("command:")
}

func parseError() {
	usage()
	flag.PrintDefaults()
	os.Exit(1)
}

func csvconv(data *db.Result) []string {
	record := []string{
		data.SoftwareName,
		data.Overview,
		data.AffectVersion,
		data.Cve,
		data.Link,
		data.Date,
	}
	return record
}

func getCve(data []parser.RelatedItem) string {
	for _, value := range data {
		if strings.Contains(value.Name, "CVE") {
			return value.VulInfoId
		}
	}
	return "None"
}

func createQueryObjct(productName string, overview parser.Item, detail parser.Detail) (query db.QueryObject) {

	query.SoftwareName = productName
	if len(detail.VulInfo.VulInfoData.Related.RelatedItem) != 0 {
		query.Cve = getCve(detail.VulInfo.VulInfoData.Related.RelatedItem[:])
	} else {
		query.Cve = "None"
	}
	query.Overview = overview.Title
	query.Identifier = overview.Identifier
	if utf8.RuneCountInString(detail.VulInfo.VulInfoData.Published) != 0 {
		query.Date = detail.VulInfo.VulInfoData.Published[:10]
	} else {
		query.Date = "None"
	}
	query.AffectVersion = detail.VulInfo.VulInfoData.Affect.AffectedItem
	if len(overview.Cvsses) > 0 {
		query.Cvss = overview.Cvsses[0].Score
	} else {
		query.Cvss = "None"
	}
	return
}
