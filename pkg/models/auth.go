package models

type User struct {
	Id       int64  `json:"id" gorm:"primaryKey"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Password string `json:"password"`
	Status string `json:"status" gorm:"default:'active'"`
}

type Admin struct {
	Id       int64  `json:"id" gorm:"primaryKey"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

