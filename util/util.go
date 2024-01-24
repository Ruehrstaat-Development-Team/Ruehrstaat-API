package util

import (
	"math"
	"ruehrstaat-backend/logging"
)

var log = logging.Logger{Package: "util"}

func RoundTo2Decimals(num float64) float64 {
	return math.Round(num*100) / 100
}

func RemoveFromSlice[T comparable](slice []T, value T) []T {
	for i, v := range slice {
		if v == value {
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice
}
