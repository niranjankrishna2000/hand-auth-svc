package services

import (
	"context"
	"errors"
	"log"
	"net/http"

	"auth-svc/pkg/db"
	"auth-svc/pkg/models"
	"auth-svc/pkg/pb"
	"auth-svc/pkg/utils"

	"github.com/spf13/viper"
)

type Server struct {
	H   db.Handler
	Jwt utils.JwtWrapper
	pb.UnimplementedAuthServiceServer
}

func (s *Server) SignUp(ctx context.Context, req *pb.SignUpRequest) (*pb.SignUpResponse, error) {
	var user models.User

	if result := s.H.DB.Where(&models.User{Email: req.Email}).First(&user); result.Error == nil {
		return &pb.SignUpResponse{
			Status: http.StatusBadRequest,
			Error:  "E-Mail already exists",
			User:   nil,
		}, result.Error
	}

	user.Email = req.Email
	user.Name = req.Name
	user.Phone = req.Phone
	user.Password = utils.HashPassword(req.Password)

	s.H.DB.Create(&user)

	return &pb.SignUpResponse{
		Status: http.StatusCreated,
		Error:  "No errors. Successfully Created",
		User:   &pb.User{Name: user.Name, Email: user.Email, Phone: user.Phone},
	}, nil
}

func (s *Server) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	var user models.User

	if result := s.H.DB.Where(&models.User{Email: req.Email}).First(&user); result.Error != nil {
		return &pb.LoginResponse{
			Status: http.StatusNotFound,
			Error:  "User not found",
			Token:  "",
			User:   nil,
		}, result.Error
	}

	match := utils.CheckPasswordHash(req.Password, user.Password)

	if !match {
		return &pb.LoginResponse{
			Status: http.StatusNotFound,
			Error:  "Password not match",
			Token:  "",
			User:   nil,
		}, errors.New("wrong password")
	}

	token, err := s.Jwt.GenerateToken(user)
	if err != nil {
		return &pb.LoginResponse{
			Status: http.StatusNotFound,
			Error:  "Could Not Generate Token",
			Token:  "",
			User:   nil,
		}, err
	}

	return &pb.LoginResponse{
		Status: http.StatusOK,
		Error: "No errors. Successfully logged In",
		Token:  "Bearer " + token,
		User:   &pb.User{Name: user.Name, Email: user.Email, Phone: user.Phone},
	}, nil
}

func (s *Server) AdminLogin(ctx context.Context, req *pb.AdminLoginRequest) (*pb.AdminLoginResponse, error) {
	var Admin models.Admin

	if result := s.H.DB.Where(&models.Admin{Email: req.Email}).First(&Admin); result.Error != nil {
		return &pb.AdminLoginResponse{
			Status: http.StatusNotFound,
			Error:  "Admin not found",
			Token: "",
		}, result.Error
	}

	match := utils.CheckPasswordHash(req.Password, Admin.Password)

	if !match {
		return &pb.AdminLoginResponse{
			Status: http.StatusNotFound,
			Error:  "password wrong",
			Token: "",
		}, errors.New("wrong Passwords")
	}

	token, err := s.Jwt.GenerateTokenAdmin(Admin)
	if err != nil {
		return &pb.AdminLoginResponse{
			Status: http.StatusNotFound,
			Error:  "Could Not Generate Token",
			Token:  "",
		}, err
	}

	return &pb.AdminLoginResponse{
		Status: http.StatusOK,
		Error: "No errors. Successfully Logged In",
		Token:  token,
	}, nil
}
func (s *Server) Validate(ctx context.Context, req *pb.ValidateRequest) (*pb.ValidateResponse, error) {
	claims, err := s.Jwt.ValidateToken(req.Token)
	if err != nil {
		return &pb.ValidateResponse{
			Status: http.StatusBadRequest,
			Error:  "Token Invalid",
		}, err
	}

	var user models.User

	if result := s.H.DB.Where(&models.User{Email: claims.Email}).First(&user); result.Error != nil {
		return &pb.ValidateResponse{
			Status: http.StatusNotFound,
			Error:  "User not found",
		}, result.Error
	}

	return &pb.ValidateResponse{
		Status: http.StatusOK,
		Error: "No errors. Successfully Validated",
		UserId: user.Id,
	}, nil
}
func (s *Server) AdminValidate(ctx context.Context, req *pb.ValidateRequest) (*pb.AdminValidateResponse, error) {
	claims, err := s.Jwt.ValidateTokenAdmin(req.Token)

	if err != nil {
		return &pb.AdminValidateResponse{
			Status: http.StatusBadRequest,
			Error:  "Token Invalid",
		}, err
	}

	var user models.Admin

	if result := s.H.DB.Where(&models.User{Email: claims.Email}).First(&user); result.Error != nil {
		return &pb.AdminValidateResponse{
			Status: http.StatusNotFound,
			Error:  "User not found",
		}, result.Error
	}

	return &pb.AdminValidateResponse{
		Status: http.StatusOK,
		Error: "No errors. Token Valid",
	}, nil
}
func (s *Server) LoginWithOtp(ctx context.Context, req *pb.LoginWithOtpRequest) (*pb.LoginWithOtpResponse, error) {
	var user models.User

	if result := s.H.DB.Where(&models.User{Phone: req.Phone}).First(&user); result.Error != nil {
		return &pb.LoginWithOtpResponse{
			Status: http.StatusNotFound,
			Error:  "User not found",
		}, result.Error
	}

	utils.TwilioSetup(viper.GetString("ACCOUNTSID"), viper.GetString("AUTHTOKEN"))
	_, err := utils.TwilioSendOTP(req.Phone, viper.GetString("SERVICESID"))
	if err != nil {
		return &pb.LoginWithOtpResponse{
			Status: http.StatusNotFound,
			Error:  "Error while generating OTP...",
		}, err
	}

	return &pb.LoginWithOtpResponse{
		Status: http.StatusOK,
		Error: "No Errors. Successfully sent Otp",
	}, nil
}
func (s *Server) OtpValidate(ctx context.Context, req *pb.OtpValidationRequest) (*pb.OtpValidationResponse, error) {
	var user models.User

	if result := s.H.DB.Where(&models.User{Phone: req.Phone}).First(&user); result.Error != nil {
		return &pb.OtpValidationResponse{
			Status: http.StatusNotFound,
			Error:  "Record not found",
			Token: "",
		}, result.Error
	}

	if req.Password != req.Confirm {
		return &pb.OtpValidationResponse{
			Status: http.StatusNotFound,
			Error:  "Password Not same",
			Token: "",
		}, errors.New("password mismatch")
	}
	utils.TwilioSetup(viper.GetString("ACCOUNTSID"), viper.GetString("AUTHTOKEN"))
	err := utils.TwilioVerifyOTP(viper.GetString("SERVICESID"), req.Otp, req.Phone)
	if err != nil {
		return &pb.OtpValidationResponse{
			Status: http.StatusNotFound,
			Error:  "error while verifying",
			Token: "",
		}, err
	}

	err = s.H.DB.Exec("UPDATE users SET password=? WHERE id=?", req.Password, user.Id).Error
	if err != nil {
		return &pb.OtpValidationResponse{
			Status: http.StatusBadGateway,
			Error:  "could not change password",
			Token: "",
		}, err
	}

	token, err := s.Jwt.GenerateToken(user)
	if err != nil {
		return &pb.OtpValidationResponse{
			Status: http.StatusBadGateway,
			Error:  "could not generate token",
			Token: "",
		}, err
	}
	return &pb.OtpValidationResponse{
		Status: http.StatusOK,
		Error: "No errors. Successfully logged in",
		Token:  token,
	}, nil
}

func (s *Server) GetUserDetails(ctx context.Context, req *pb.GetUserDetailsRequest) (*pb.GetUserDetailsResponse, error) {
	log.Println("started Collecting user details")
	var user models.User

	if result := s.H.DB.Where(&models.User{Id: int64(req.Userid)}).First(&user); result.Error != nil {
		return &pb.GetUserDetailsResponse{
			Status: http.StatusNotFound,
			Error:  "User not found",
			User: nil,
		}, result.Error
	}

	return &pb.GetUserDetailsResponse{
		Status: http.StatusOK,
		User:   &pb.User{Name: user.Name, Email: user.Email, Phone: user.Phone},
		Error: "No errors. Successfully obtained user",
	}, nil
}

func (s *Server) ChangeUserPermission(ctx context.Context, req *pb.ChangeUserPermissionRequest) (*pb.ChangeUserPermissionResponse, error) {

	log.Println("Change User Permission started")

	var userdetails *pb.User

	if err := s.H.DB.Raw("SELECT * FROM users where id=?", req.Id).Scan(&userdetails).Error; err != nil {
		return &pb.ChangeUserPermissionResponse{
			Status: http.StatusBadRequest,
			Error:  "couldn't get user from DB",
			User: nil,
		}, err
	}
	if userdetails.Status == "active" {
		userdetails.Status = "blocked"
	} else if userdetails.Status == "blocked" {
		userdetails.Status = "active"
	}
	err := s.H.DB.Exec("UPDATE users set status = ? where id = ?", userdetails.Status, req.Id).Error
	if err != nil {
		log.Println(err)
		return &pb.ChangeUserPermissionResponse{Status: http.StatusBadGateway, Error: "Couldnt update permission"}, err
	}

	log.Println("user:", userdetails)
	return &pb.ChangeUserPermissionResponse{
		Status: http.StatusOK,
		Error:  "",
		User:   userdetails,
	}, nil

}

func (s *Server) UserList(ctx context.Context, req *pb.UserListRequest) (*pb.UserListResponse, error) {

	log.Println("User collection started")
	log.Println("Data collected", req)
	var page, limit int64
	page, limit = int64(req.Page), int64(req.Limit)
	// pagination purpose -
	if req.Page == 0 {
		page = 1
	}
	if req.Limit == 0 {
		limit = 10
	}
	offset := (page - 1) * limit
	var userdetails []*pb.User

	sqlQuery := "SELECT * FROM users "
	if req.Searchkey != "" {
		sqlQuery += " WHERE name ILIKE '%" + req.Searchkey + "%' OR email ILIKE '%" + req.Searchkey + "%' OR phone ILIKE '%" + req.Searchkey + "%'"
	}
	sqlQuery += "LIMIT ? OFFSET ?"

	if err := s.H.DB.Raw(sqlQuery, limit, offset).Scan(&userdetails).Error; err != nil {
		return &pb.UserListResponse{
			Status: http.StatusBadRequest,
			Error:  "couldn't get posts from DB",
			User:   []*pb.User{},
		}, err
	}
	log.Println("users:", userdetails)
	return &pb.UserListResponse{
		Status: http.StatusOK,
		Error:  "",
		User:   userdetails,
	}, nil

}
