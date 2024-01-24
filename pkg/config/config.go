package config

import "github.com/spf13/viper"

type Config struct {
    Port         string `mapstructure:"PORT"`
    DBUrl        string `mapstructure:"DB_URL"`
    JWTSecretKey string `mapstructure:"JWT_SECRET_KEY"`
    ACCOUNTSID string `mapstructure:"ACCOUNTSID"`
	SERVICESID string `mapstructure:"SERVICESID"`
	AUTHTOKEN  string `mapstructure:"AUTHTOKEN"`
}

func LoadConfig() (config Config, err error) {
    viper.AddConfigPath("./pkg/config/envs")
    viper.SetConfigName("dev")
    viper.SetConfigType("env")

    viper.AutomaticEnv()

    err = viper.ReadInConfig()

    if err != nil {
        return
    }

    err = viper.Unmarshal(&config)

    return
}