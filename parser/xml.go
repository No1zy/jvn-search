package parser

import (
	"encoding/xml"
)

type Response struct {
	Item []Item `xml:"item"`
	ResInfo     Status       `xml:"http://jvndb.jvn.jp/myjvn/Status Status"`
}

type Item struct {
	About       string       `xml:"about,attr"`
	Title       string       `xml:"title"`
	Link        string       `xml:"link"`
	Description string       `xml:"description"`
	Publisher   string       `xml:"publisher"`
	Identifier  string       `xml:"identifier"`
	References  []references `xml:"references"`
	Cpes        []cpe        `xml:"cpe"`
	Cvsses      []Cvss       `xml:"cvss"`
	Date        string       `xml:"date"`
	Issued      string       `xml:"issued"`
	Modified    string       `xml:"modified"`
}

type cpe struct {
	Version string `xml:"version,attr"` // cpe:/a:mysql:mysql
	Vendor  string `xml:"vendor,attr"`
	Product string `xml:"product,attr"`
	Value   string `xml:",chardata"`
}

type references struct {
	ID     string `xml:"id,attr"`
	Source string `xml:"source,attr"`
	Title  string `xml:"title,attr"`
	URL    string `xml:",chardata"`
}

// Cvss ... CVSS
type Cvss struct {
	Score    string `xml:"score,attr"`
	Severity string `xml:"severity,attr"`
	Vector   string `xml:"vector,attr"`
	Version  string `xml:"version,attr"`
}

type Status struct {
	TotalRes    int `xml:"totalRes,attr"`
	totalResRet int `xml:"totalResRet,attr"`
}
// ref
type Detail struct {
	VulInfo    VulnInfo `xml:"Vulinfo"`
	VulnInfoId string   `xml:"VulinfoID"`
}

type VulnInfo struct {
	VulInfoId   string       `xml:"VulinfoID"`
	VulInfoData VulnInfoData `xml:"VulinfoData"`
}

type VulnInfoData struct {
	Affect    Affected `xml:"Affected"`
	Related   Related  `xml:"Related"`
	Published string   `xml:"DateLastUpdated"`
}

type Related struct {
	RelatedItem []RelatedItem `xml:"RelatedItem"`
}

type Affected struct {
	AffectedItem []AffectedItem `xml:"AffectedItem"`
}

type RelatedItem struct {
	Name      string `xml:"Name"`
	VulInfoId string `xml:"VulinfoID"`
}

type AffectedItem struct {
	ProductName   string `xml:"ProductName"`
	VersionNumber string `xml:"VersionNumber"`
}



func CreateDetail(body []byte) Detail {
	items := Detail{}
	xml.Unmarshal(body, &items)
	return items
}

func CreateInfo(body []byte) *Response {
	items := Response{}
	xml.Unmarshal(body, &items)
	return &items
}

