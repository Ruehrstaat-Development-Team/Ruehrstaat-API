package serialize

import (
	"ruehrstaat-backend/logging"

	"github.com/gin-gonic/gin"
)

var log = logging.Logger{Package: "serialize"}

type Serializer[T any] interface {
	Serialize(obj T) interface{}
}

// Shortcut for serializer.Serialize(obj)
func Do[T any](serializer Serializer[T], obj T) interface{} {
	return serializer.Serialize(obj)
}

// Shortcut for serializer.Serialize(obj) for each obj in objs
func DoArray[T any](serializer Serializer[T], objs []T) []interface{} {
	result := make([]interface{}, len(objs))
	for i, obj := range objs {
		result[i] = Do[T](serializer, obj)
	}
	return result
}

func DoVarargs[T any](serializer Serializer[T], objs ...T) []interface{} {
	return DoArray[T](serializer, objs)
}

func JSON[T any](c *gin.Context, serializer Serializer[T], obj T) {
	c.JSON(200, Do[T](serializer, obj))
}

func JSONArray[T any](c *gin.Context, serializer Serializer[T], objs []T) {
	c.JSON(200, DoArray[T](serializer, objs))
}

func JSONVarargs[T any](c *gin.Context, serializer Serializer[T], objs ...T) {
	c.JSON(200, DoVarargs[T](serializer, objs...))
}
