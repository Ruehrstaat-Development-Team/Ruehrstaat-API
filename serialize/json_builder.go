package serialize

type JsonObj map[string]interface{}

func (obj *JsonObj) Add(key string, value interface{}) {
	(*obj)[key] = value
}
