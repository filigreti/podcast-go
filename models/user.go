package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type User struct {
	Id         primitive.ObjectID `bson:"_id,omitempty"`
	Username   string             `json:"username,omitempty" validate:"required"`
	Email      string             `json:"email,omitempty"  validate:"required,email"`
	Password   string             `json:"password,omitempty"  validate:"required"`
	IsVerified *bool              `json:"is_verified,omitempty" bson:"is_verified,omitempty"`
}

type Login struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type RedisVerification struct {
	Email             string
	VerificationToken string
	IsVerified        bool
}
