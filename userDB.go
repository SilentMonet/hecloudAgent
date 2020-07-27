package main

import (
	"database/sql"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
)

func getLastCookie(user *userInfo) (cookie cookie) {
	db, err := sql.Open("mysql", "root:0000009@tcp(127.0.0.1:3306)/caiCloud")
	if err != nil {
		fmt.Println(err)
	}
	defer db.Close()
	row := db.QueryRow("select * from user")
	err = row.Scan(&user.name, &user.encryptedPassword, &cookie.sid, &cookie.RMKEY)
	if err != nil {
		fmt.Println(err)
	}
	return cookie
}

func updateCookie(user userInfo, cookie cookie) {
	db, err := sql.Open("mysql", "root:00000009@tcp(127.0.0.1:3306)/caiCloud")
	if err != nil {
		fmt.Println(err)
	}
	defer db.Close()
	_, err = db.Exec("UPDATE  user SET sid=?,RMKEY=? WHERE name=?", cookie.sid, cookie.RMKEY, user.name)
	if err != nil {
		fmt.Println(err)
	}
}
