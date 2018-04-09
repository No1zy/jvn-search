package db

import (
	"database/sql"
	"github.com/No1zy/jvn_search/parser"
	_ "github.com/mattn/go-sqlite3"
	"log"
	//"fmt"
)

type Result struct {
	SoftwareName  string
	Cve           string
	Overview      string
	Link          string
	Date          string
	Identifier    string
	Cvss          string
	AffectVersion string
}

type QueryObject struct {
	SoftwareName  string
	Cve           string
	Overview      string
	Link          string
	Date          string
	Identifier    string
	Cvss          string
	AffectVersion []parser.AffectedItem
}

type DB interface {
	Name() string
	CloseDB() error
	InsertJvn([]parser.Item) error
}

func New() (db *sql.DB) {
	db, err := sql.Open("sqlite3", "file:dictionary.db")
	if err != nil {
		log.Fatal(err)
	}
	_, err = db.Exec(
		`CREATE TABLE IF NOT EXISTS "Vulnerability_Dictionary" (
		"id" INTEGER PRIMARY KEY AUTOINCREMENT,
		"software_name" VARCHAR(255),
		"cve" VARCHAR(30), 
		"title" VARCHAR(255),
		"link" VARCHAR(255),
		"date" VARCHAR(255),
		"identifier" VARCHAR(255),
		"cvss" VARCHAR(255),
		"affected" VARCHAR(255)
	)`)
	if err != nil {
		log.Fatal(err)
	}
	return db
}

func InsertJVN(db *sql.DB, jvn *QueryObject) {
	var versions string
	for _, affected := range jvn.AffectVersion {
		versions += affected.ProductName + affected.VersionNumber + "\n"
	}
	sql := `INSERT INTO Vulnerability_Dictionary (
			software_name,
			cve,
			title,
			link,
			date,
			identifier,
			cvss,
			affected
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	tx, err := db.Begin()
	if err != nil {
		log.Fatal(err)
	}
	stmt, err := tx.Prepare(sql)
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close()
	_, err = stmt.Exec(
		jvn.SoftwareName,
		jvn.Cve,
		jvn.Overview,
		jvn.Link,
		jvn.Date,
		jvn.Identifier,
		jvn.Cvss,
		versions,
	)
	if err != nil {
		log.Fatal(err)
	}
	tx.Commit()
}

func Exists(db *sql.DB, jvnId string) bool {
	sql := `select count(*) from Vulnerability_Dictionary where identifier = ?`
	stmt, err := db.Prepare(sql)
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close()
	var count int
	err = stmt.QueryRow(jvnId).Scan(&count)
	if err != nil {
		log.Fatal(err)
	}
	if count > 0 {
		//fmt.Println("exsits identifier", jvnId)
		//fmt.Println("count : ", count)
		return true
	} else {
		return false
	}
}

func GetProduct(db *sql.DB, productName string) []Result {
	sql := `select software_name, cve, title, link, date,
			identifier, cvss, affected from Vulnerability_Dictionary where software_name = ?`
	rows, err := db.Query(sql, productName)
	defer rows.Close()
	if err != nil {
		log.Fatal(err)
	}
	if err != nil {
		log.Fatal(err)
	}
	result := make([]Result, 0)
	for rows.Next() {
		row := Result{}
		var (
			software_name string
			cve string
			title string
			link string
			date string
			identifier string
			cvss string
			affected string
		)
		rows.Scan(
			&software_name,
			&cve,
			&title,
			&link,
			&date,
			&identifier,
			&cvss,
			&affected,
		)
		row.SoftwareName = software_name
		row.Cve = cve
		row.Overview = title
		row.Link = link
		row.Date = date
		row.Identifier = identifier
		row.Cvss = cvss
		row.AffectVersion = affected

		result = append(result, row)
	}
	return result
}

func GetCount(db *sql.DB, product string) int {
	sql := `select count(*) from Vulnerability_Dictionary where software_name = ?`
	var count int
	err := db.QueryRow(sql, product).Scan(&count)
	if err != nil {
		log.Fatal(err)
	}
	return count
}

