package controllers

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/filigreti/podcast-backend/configs"
	"github.com/filigreti/podcast-backend/models"
	responses "github.com/filigreti/podcast-backend/utils"
	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/gomail.v2"
)

var userCollection *mongo.Collection = configs.GetCollection(configs.DB, "users")
var redisClient *redis.Client = configs.GetRedisClient()
var validate = validator.New()
var jwtSecret = []byte(configs.GetEnv("SECRET_KEY"))

const verificationTokenExpiration = 24 * time.Hour
const (
	smtpHost        = "smtp.gmail.com"
	smtpPort        = 587
	smtpSenderEmail = "aolfiligre@gmail.com"
)

func CreateUser(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	var user models.User
	defer cancel()

	if err := c.Bind(&user); err != nil {
		return c.JSON(http.StatusBadRequest, responses.UserResponse{Status: http.StatusBadRequest, Message: "error", Data: &echo.Map{"data": err.Error()}})
	}

	if validationErr := validate.Struct(&user); validationErr != nil {
		return c.JSON(http.StatusBadRequest, responses.UserResponse{Status: http.StatusBadRequest, Message: "error", Data: &echo.Map{"data": validationErr.Error()}})
	}

	existingUser := models.User{}
	err := userCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&existingUser)
	if err == nil {
		// Email already exists, return an error
		return c.JSON(http.StatusConflict, responses.UserResponse{Status: http.StatusConflict, Message: "error", Data: &echo.Map{"data": "Email already exists"}})
	} else if err != mongo.ErrNoDocuments {
		// Some other error occurred
		return c.JSON(http.StatusInternalServerError, responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &echo.Map{"data": err.Error()}})
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &echo.Map{"data": err.Error()}})
	}

	newUser := models.User{
		Username: user.Username,
		Email:    user.Email,
		Password: string(hashedPassword),
	}

	result, err := userCollection.InsertOne(ctx, newUser)

	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &echo.Map{"data": err.Error()}})
	}

	verificationToken, err := generateVerificationToken()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &echo.Map{"data": err.Error()}})
	}

	err = sendVerificationEmail(newUser.Email, newUser.Username, verificationToken)
	if err != nil {
		fmt.Println("herror:", err)
		return c.JSON(http.StatusInternalServerError, responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &echo.Map{"data": err.Error()}})
	}

	responseData := &echo.Map{"data": result, "emailSent": true}

	return c.JSON(http.StatusCreated, responses.UserResponse{Status: http.StatusCreated, Message: "success", Data: &echo.Map{"data": responseData}})
}

func GetUser(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Retrieve the user ID from the context set by the token middleware
	userID, ok := c.Get("user").(string)
	println("User ID, why now: ", userID)
	if !ok {
		return c.JSON(http.StatusUnauthorized, responses.UserResponse{Status: http.StatusUnauthorized, Message: "error", Data: &echo.Map{"data": "User ID not found in context"}})
	}

	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, responses.UserResponse{Status: http.StatusBadRequest, Message: "error", Data: &echo.Map{"data": "Invalid user ID format"}})
	}

	var user models.User
	err = userCollection.FindOne(ctx, bson.M{"_id": objID}).Decode(&user)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &echo.Map{"data": err.Error()}})
	}
	userMap := echo.Map{
		"id":       user.Id,
		"username": user.Username,
		"email":    user.Email,
	}

	return c.JSON(http.StatusOK, responses.UserResponse{Status: http.StatusOK, Message: "success", Data: &echo.Map{"data": userMap}})
}

func UserLogin(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var loginData models.Login

	if err := c.Bind(&loginData); err != nil {
		return c.JSON(http.StatusBadRequest, responses.UserResponse{Status: http.StatusBadRequest, Message: "error", Data: &echo.Map{"data": err.Error()}})
	}

	if validationErr := validate.Struct(loginData); validationErr != nil {
		return c.JSON(http.StatusBadRequest, responses.UserResponse{Status: http.StatusBadRequest, Message: "error", Data: &echo.Map{"data": validationErr.Error()}})
	}

	// Find the user by email
	user := models.User{}
	err := userCollection.FindOne(ctx, bson.M{"email": loginData.Email}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.JSON(http.StatusUnauthorized, responses.UserResponse{Status: http.StatusUnauthorized, Message: "error", Data: &echo.Map{"data": "Invalid credentials"}})
		}
		return c.JSON(http.StatusInternalServerError, responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &echo.Map{"data": err.Error()}})
	}

	// Check if the email is verified
	if user.IsVerified == nil || !*user.IsVerified {
		return c.JSON(http.StatusUnauthorized, responses.UserResponse{Status: http.StatusUnauthorized, Message: "error", Data: &echo.Map{"data": "Email not verified. Please verify your email before logging in."}})
	}

	// Compare hashed password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginData.Password))
	if err != nil {
		return c.JSON(http.StatusUnauthorized, responses.UserResponse{Status: http.StatusUnauthorized, Message: "error", Data: &echo.Map{"data": "Invalid credentials"}})
	}

	token, err := generateJwtToken(user.Id.Hex())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &echo.Map{"data": err.Error()}})
	}
	return c.JSON(http.StatusOK, responses.UserResponse{Status: http.StatusOK, Message: "success", Data: &echo.Map{"token": token}})
}

func VerifyEmail(c echo.Context) error {
	token := c.Param("token")
	if token == "" {
		return c.JSON(http.StatusBadRequest, responses.UserResponse{Status: http.StatusBadRequest, Message: "error", Data: &echo.Map{"data": "Token is required"}})
	}

	// Validate the token and update the user's verification status in the database
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Retrieve the email verification details from Redis
	key := fmt.Sprintf("verification:%s", token)
	verificationDetails, err := redisClient.HGetAll(ctx, key).Result()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &echo.Map{"data": err.Error()}})
	}

	email, ok := verificationDetails["email"]
	if !ok {
		return c.JSON(http.StatusBadRequest, responses.UserResponse{Status: http.StatusBadRequest, Message: "error", Data: &echo.Map{"data": "Invalid verification token"}})
	}

	// Update the user's verification status in the database
	userUpdate := bson.M{"$set": bson.M{"is_verified": true}}
	_, err = userCollection.UpdateOne(ctx, bson.M{"email": email}, userUpdate)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &echo.Map{"data": err.Error()}})
	}

	// Optionally, remove the verification details from Redis after successful verification
	err = redisClient.Del(ctx, key).Err()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &echo.Map{"data": err.Error()}})
	}

	return c.JSON(http.StatusOK, responses.UserResponse{Status: http.StatusOK, Message: "success", Data: &echo.Map{"data": "Email verified successfully"}})
}

// This needs to be moved into the utils folder
func generateJwtToken(userID string) (string, error) {
	// Create a new JWT token
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["sub"] = userID
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix() // Token expires in 24 hours

	// Sign the token with a secret key
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func generateVerificationToken() (string, error) {
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	token := base64.URLEncoding.EncodeToString(randomBytes)
	return token, nil
}

func sendVerificationEmail(email, username, verificationToken string) error {
	user := models.RedisVerification{
		Email:             email,
		VerificationToken: verificationToken,
		IsVerified:        false,
	}

	ctx := context.Background()
	key := fmt.Sprintf("verification:%s", verificationToken)
	err := redisClient.HMSet(ctx, key, map[string]interface{}{
		"email":             user.Email,
		"verificationToken": user.VerificationToken,
		"isVerified":        user.IsVerified,
	}).Err()

	if err != nil {
		return err
	}

	err = redisClient.Expire(ctx, key, verificationTokenExpiration).Err()
	if err != nil {
		return err
	}

	err = sendGomail("/email.html", verificationToken, email, username)
	if err != nil {
		return err
	}

	return nil
}
func sendGomail(path, token, email, username string) error {
	var body bytes.Buffer
	t, err := template.ParseFiles("templates/email.html")

	if err != nil {
		return err
	}

	type EmailTemplateData struct {
		VerificationLink string
		Username         string
	}

	data := EmailTemplateData{
		VerificationLink: fmt.Sprintf("%s/verify-email/%s", configs.GetEnv("BASE_URL"), token),
		Username:         username,
	}

	err = t.Execute(&body, data)
	if err != nil {
		log.Println("Error executing template:", err)
		return err
	}

	m := gomail.NewMessage()
	m.SetHeader("From", smtpSenderEmail)
	m.SetHeader("To", email)
	m.SetHeader("Subject", "Email Verification")
	m.SetBody("text/html", body.String())

	d := gomail.NewDialer(smtpHost, smtpPort, smtpSenderEmail, configs.GetEnv("GOOGLE_PASSWORD"))

	if err := d.DialAndSend(m); err != nil {
		log.Println("Error sending email:", err)
		return err
	}

	return nil
}
