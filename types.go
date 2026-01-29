package main

type Response struct {
	Status bool `json:"status"`
	Data   any  `json:"data"`
	// Empty if status is True
	Message string `json:"message"`
}
