package main

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mgo.v2"
)

type obj map[string]interface{}

type User struct {
	Nickname  string `form:"nickname" bson:"_id" json:"nickname"`
	Password  string `form:"password" bson:"password" json:"password"`
	Firstname string `bson:"firstname" json:"firstname"`
	Lastname  string `bson:"lastname" json:"lastname"`
	Age       int    `bson:"age" json:"age"`
}

type UsersCache struct {
	m map[string]User
	sync.RWMutex
}

func ToHash(s string) string {
	bytes, _ := bcrypt.GenerateFromPassword([]byte(s), 14)
	return string(bytes)
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func addUserToDB(s *mgo.Session, u User) (err error) {
	c := s.DB("main").C("users")
	err = c.Insert(u)
	return err
}

func getUserFromDB(s *mgo.Session, u User) (res User) {
	c := s.DB("main").C("users")
	c.FindId(u.Nickname).One(&res)
	return

}

func registerUser(c *gin.Context) {
	session, err := mgo.Dial("mongodb://localhost:27017")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	defer session.Close()
	session.SetMode(mgo.Monotonic, true)
	var usr User
	c.Bind(&usr)

	usr.Password = ToHash(usr.Password)
	usrFromDB := getUserFromDB(session, usr)
	if (usrFromDB == User{}) {
		err = addUserToDB(session, usr)
		if err != nil {
			fmt.Println(err.Error())
		}
		c.String(http.StatusOK, fmt.Sprintf("New user %v found, welcome!", string(usr.Nickname)))
	} else {
		c.String(http.StatusOK, fmt.Sprintf("user %v is already exists", string(usr.Nickname)))
	}
}

func identifyUser(c *gin.Context) {
	session, err := mgo.Dial("mongodb://localhost:27017")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	defer session.Close()
	session.SetMode(mgo.Monotonic, true)
	var usr User
	c.Bind(&usr)

	usrFromDB := getUserFromDB(session, usr)

	if (usrFromDB != User{}) && CheckPasswordHash(usr.Password, usrFromDB.Password) {
		c.String(http.StatusOK, fmt.Sprintf("Logged in as %v", string(usr.Nickname)))
		cookie, err := c.Cookie("gin_cookie")
		if err != nil {
			cookie = ToHash(string(usr.Nickname))
			c.SetCookie("gin_cookie", cookie, 3600, "/", "localhost", false, false)
		}

		fmt.Printf("Cookie value: %s \n", cookie)

	} else {
		c.String(http.StatusOK, fmt.Sprintln("Wrong login or password"))
	}
}

func main() {
	r := gin.Default()
	r.POST("/register", registerUser)
	r.POST("/login", identifyUser)
	r.Run()
}
