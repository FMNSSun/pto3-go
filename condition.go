package pto3

import (
	"net/http"
	"strings"

	"github.com/go-pg/pg/orm"
)

type Condition struct {
	ID   int
	Name string
}

// FIXME consider replacing this with a condition cache everywhere
func (c *Condition) InsertOnce(db orm.DB) error {
	if c.ID == 0 {
		_, err := db.Model(c).
			Column("id").
			Where("name=?name").
			Returning("id").
			SelectOrInsert()
		if err != nil {
			return PTOWrapError(err)
		}
	}
	return nil
}

// FIXME consider replacing this with a condition cache everywhere
func (c *Condition) SelectByID(db orm.DB) error {
	return db.Select(c)
}

// ConditionCache maps a condition name to a condition ID
type ConditionCache map[string]int

// FillConditionIDsInSet ensures all the conditions in a given observation set
// have valid IDs. It keeps the condition cache synchronized with the database
// if any new conditions have been added.
func (cache ConditionCache) FillConditionIDsInSet(db orm.DB, set *ObservationSet) error {

	for _, c := range set.Conditions {
		if err := cache.SetConditionID(db, &c); err != nil {
			return err
		}
	}

	return nil
}

// SetConditionID ensures the given condition has a valid ID. It keeps the
// condition cache synchronized with the database if the condition is new.
func (cache ConditionCache) SetConditionID(db orm.DB, c *Condition) error {
	// check for a cache hit
	id, ok := cache[c.Name]
	if ok {
		c.ID = id
		return nil
	}

	// check to see if we need to insert or retrieve from DB
	if c.ID == 0 {
		if err := c.InsertOnce(db); err != nil {
			return err
		}
	}

	// now cache
	cache[c.Name] = c.ID
	return nil
}

func (cache ConditionCache) Reload(db orm.DB) error {
	var conditions []Condition

	if err := db.Model(&conditions).Select(); err != nil {
		return PTOWrapError(err)
	}

	for _, c := range conditions {
		cache[c.Name] = c.ID
	}

	return nil
}

func (cache ConditionCache) ConditionsByName(db orm.DB, conditionName string) ([]Condition, error) {
	var out []Condition

	if strings.HasSuffix(conditionName, ".*") {
		// Wildcard. Reload cache and find everything that matches.
		if err := cache.Reload(db); err != nil {
			return nil, err
		}
		out = make([]Condition, 0)
		for cachedName := range cache {
			if strings.HasPrefix(cachedName, conditionName[:len(conditionName)-1]) {
				out = append(out, Condition{Name: cachedName, ID: cache[cachedName]})
			}
		}
	} else {
		// No wildcard, just look up by name.
		if cache[conditionName] == 0 {
			if err := cache.Reload(db); err != nil {
				return nil, err
			}
		}
		if cache[conditionName] == 0 {
			return nil, PTOErrorf("unknown condition %s", conditionName).StatusIs(http.StatusBadRequest)
		}
		out = make([]Condition, 1)
		out[0] = Condition{Name: conditionName, ID: cache[conditionName]}
	}

	return out, nil
}

// LoadConditionCache creates a new condition cache with all the conditions in a given database.
func LoadConditionCache(db orm.DB) (ConditionCache, error) {

	cache := make(ConditionCache)

	if err := cache.Reload(db); err != nil {
		return nil, err
	}

	return cache, nil

}
