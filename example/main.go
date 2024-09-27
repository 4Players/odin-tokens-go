package main

import (
	"fmt"

	odin_tokens "github.com/4Players/odin-tokens-go"
)

func main() {
	// Example usage
	accessKey, _ := odin_tokens.GenerateAccessKey()
	fmt.Println("Generated Access Key:", accessKey)

	tokenGenerator, _ := odin_tokens.NewTokenGenerator(accessKey)
	token, _ := tokenGenerator.CreateToken("room123", "user123", odin_tokens.TokenOptions{Customer: "exampleCustomer", Lifetime: 300})
	fmt.Println("Generated Token:", token)
}
