package jvn

import (
	"fmt"
	"log"
	"strconv"
	"net/http"
	//"github.com/parnurzeal/gorequest"
	"github.com/No1zy/jvn_search/parser"
	"github.com/No1zy/jvn_search/util"
	"io/ioutil"
	"net/url"
)

type RequestParams struct {
	Keyword string
	StartItem string
	MaxCountItem string
}

func getTotalRes(params *RequestParams) int {
	apiUrl := "https://jvndb.jvn.jp/myjvn"
	values := &url.Values{}
	values.Add("method", "getVulnOverviewList")
	values.Add("keyword", params.Keyword)
	values.Add("rangeDatePublic", "n")
	values.Add("rangeDatePublished", "n")
	values.Add("feed", "hnd")
	values.Add("rangeDateFirstPublished", "n")
	values.Add("startItem", params.StartItem)
	values.Add("maxCountItem", "1")
	resp, err := http.Get(apiUrl + "?" + values.Encode())
	if err != nil {
		fmt.Printf("error\n")
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	response := parser.CreateInfo(body)
	return response.ResInfo.TotalRes
}

func makeJvnParams(param RequestParams) (params []RequestParams) {
	var total int
	total = getTotalRes(&param)
	for i := 1; i <= total; i += 50 {
		param.StartItem = strconv.Itoa(i)
		params = append(params, param)
	}
	return
}

func FetchJvn(param RequestParams) (infoItems []parser.Item) {
	params := makeJvnParams(param)
	infoItems = fetchJvnOverviewConcurrently(params)
	return
}

func fetchJvnOverviewConcurrently(params []RequestParams) []parser.Item {

	reqChan := make(chan RequestParams, len(params))
	resChan := make(chan []parser.Item, len(params))

	defer close(reqChan)
	defer close(resChan)

	worker := util.GenWorkers(len(params))

	go func() {
		for _, param := range params {
			reqChan <- param
		}
	}()
	
	for range params {
		worker <- func() {
			select {
				case param := <-reqChan:
					resChan <- fetchJvnOverview(param)
			}
		}
	}

	items := make([]parser.Item, 0)
	for range params {
		select {
			case item := <-resChan:
				items = append(items, item...)
		}
	}
	//fmt.Println(items)
	return items
}

func fetchJvnDetailConcurrently(items []parser.Item) []parser.Detail {
	reqChan := make(chan string, len(items))
	resChan := make(chan parser.Detail, len(items))

	defer close(reqChan)
	defer close(resChan)

	worker := util.GenWorkers(len(items))

	go func() {
		for _, item := range items {
			reqChan <- item.Identifier
		}
	}()
	
	for range items {
		worker <- func() {
			select {
				case vulnId := <-reqChan:
					resChan <- FetchJvnDetail(vulnId)
			}
		}
	}

	result := make([]parser.Detail, 0)
	for range items {
		select {
			case item := <-resChan:
				result = append(result, item)
		}
	}
	return result
}


func fetchJvnOverview(param RequestParams) []parser.Item {
	apiUrl := "https://jvndb.jvn.jp/myjvn"
	values := &url.Values{}
	values.Add("method", "getVulnOverviewList")
	values.Add("keyword", param.Keyword)
	values.Add("rangeDatePublic", "n")
	values.Add("feed", "hnd")
	values.Add("rangeDatePublished", "n")
	values.Add("rangeDateFirstPublished", "n")
	values.Add("startItem", param.StartItem)
	resp, err := http.Get(fmt.Sprintf("%s?%s",apiUrl, values.Encode()))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	response := parser.CreateInfo(body)
	return response.Item
}

func FetchJvnDetail(vulnId string) parser.Detail {
	apiUrl := "https://jvndb.jvn.jp/myjvn"
	values := url.Values{}
	values.Add("method", "getVulnDetailInfo")
	values.Add("feed", "hnd")
	values.Add("vulnId", vulnId)

	resp, err := http.Get(fmt.Sprintf("%s?%s",apiUrl, values.Encode()))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	response := parser.CreateDetail(body)
	return response
}
