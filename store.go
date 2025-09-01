package envenc

import "github.com/dracory/dataobject"

// store represents the vault
//
// The store extends DataObject to store the data as key/value pairs in memory
// and provides a convenient method to serialize and deserialize it to JSON
type store struct {
	dataobject.DataObject
}

// newStore creates a new empty store
func newStore() *store {
	o := &store{
		DataObject: *dataobject.New(),
	}
	return o
}

// newStoreFromJSON creates a store from a JSON string
func newStoreFromJSON(json string) (*store, error) {
	o := &store{}

	do, err := dataobject.NewFromJSON(json)

	if err != nil {
		return nil, err
	}

	o.Hydrate(do.Data())

	return o, nil
}

// ToJSON converts the store data to a JSON string
func (o *store) ToJSON() (string, error) {
	json, err := o.DataObject.ToJSON()

	if err != nil {
		return "{}", err
	}

	if json == "null" {
		return "{}", nil
	}

	return json, nil
}

// Remove removes a key from the store
func (o *store) Remove(key string) *store {
	data := o.Data()
	delete(data, key)
	o.Hydrate(data)
	return o
}
