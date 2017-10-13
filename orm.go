package pto3

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/go-pg/pg"
	"github.com/go-pg/pg/orm"
)

// Observation data model for PTO3 obs and query
// including PostgreSQL object-relational mapping

// Time format for ISO8601 without timezone (everything is always UTC)
const ISO8601Format = "2006-01-02T15:04:05"

type Condition struct {
	ID   int
	Name string
}

func (c *Condition) InsertOnce(db orm.DB) error {
	if c.ID == 0 {
		_, err := db.Model(c).
			Column("id").
			Where("name=?name").
			Returning("id").
			SelectOrInsert()
		if err != nil {
			return err
		}
	}
	return nil
}

type Path struct {
	ID     int
	String string
}

func (p *Path) InsertOnce(db orm.DB) error {
	if p.ID == 0 {
		_, err := db.Model(p).
			Column("id").
			Where("string=?string").
			Returning("id").
			SelectOrInsert()
		if err != nil {
			return err
		}
	}
	return nil
}

type ObservationSet struct {
	ID       int
	Sources  []string `pg:",array"`
	Analyzer string
	Metadata map[string]string
}

// MarshalJSON turns this observation set into a JSON observation set metadata
// object suitable for use with the PTO API or as a line in an Observation Set
// File.
func (set *ObservationSet) MarshalJSON() ([]byte, error) {
	jmap := make(map[string]interface{})

	jmap["_sources"] = set.Sources
	jmap["_analyzer"] = set.Analyzer

	for k, v := range set.Metadata {
		jmap[k] = v
	}

	return json.Marshal(jmap)
}

// UnmarshalJSON fills in an observation set from a JSON observation set
// metadata object suitable for use with the PTO API.
func (set *ObservationSet) UnmarshalJSON(b []byte) error {
	set.Metadata = make(map[string]string)

	var jmap map[string]interface{}
	err := json.Unmarshal(b, &jmap)
	if err != nil {
		return err
	}

	// zero ID, it will be assigned on insertion anyway
	set.ID = 0

	var ok bool
	for k, v := range jmap {
		switch k {
		case "_sources":
			set.Sources, ok = AsStringArray(v)
			if !ok {
				return errors.New("_sources not a string array")
			}
		case "_analyzer":
			set.Analyzer = AsString(v)
		default:
			set.Metadata[k] = AsString(v)
		}
	}

	// make sure we got values for everything
	if set.Sources == nil {
		return errors.New("ObservationSet missing _sources")
	}

	if set.Analyzer == "" {
		return errors.New("ObservationSet missing _analyzer")
	}

	return nil
}

func (set *ObservationSet) Insert(db orm.DB, force bool) error {
	if force {
		set.ID = 0
	}
	if set.ID == 0 {
		return db.Insert(set)
	} else {
		return nil
	}
}

type Observation struct {
	ID          int
	SetID       int
	Set         *ObservationSet
	Start       time.Time
	End         time.Time
	PathID      int
	Path        *Path
	ConditionID int
	Condition   *Condition
	Value       int
}

// MarshalJSON turns this observation into a JSON array  suitable for use as a
// line in an Observation Set File.
func (obs *Observation) MarshalJSON() ([]byte, error) {
	jslice := []string{
		fmt.Sprintf("%d", obs.SetID),
		obs.Start.Format(ISO8601Format),
		obs.End.Format(ISO8601Format),
		obs.Path.String,
		obs.Condition.Name,
	}

	if obs.Value != 0 {
		jslice = append(jslice, strconv.Itoa(obs.Value))
	}

	return json.Marshal(&jslice)
}

// UnmarshalJSON fills in this observation from a JSON array line in an
// Observation Set File.
func (obs *Observation) UnmarshalJSON(b []byte) error {
	var jslice []string

	err := json.Unmarshal(b, &jslice)
	if err != nil {
		return err
	}

	if len(jslice) < 5 {
		return errors.New("Observation requires at least five elements")
	}

	obs.ID = 0
	obs.SetID, err = strconv.Atoi(jslice[0]) // fill in Set ID, will be ignored by force insert

	obs.Start, err = time.Parse(ISO8601Format, jslice[1])
	if err != nil {
		return err
	}
	obs.End, err = time.Parse(ISO8601Format, jslice[2])
	if err != nil {
		return err
	}
	obs.Path = &Path{String: jslice[3]}
	obs.Condition = &Condition{Name: jslice[4]}

	if len(jslice) >= 6 {
		obs.Value, err = strconv.Atoi(jslice[5])
		if err != nil {
			return err
		}
	}

	return nil
}

func (obs *Observation) InsertInSet(db orm.DB, set *ObservationSet) error {
	if err := obs.Path.InsertOnce(db); err != nil {
		return err
	}
	obs.PathID = obs.Path.ID

	if err := obs.Condition.InsertOnce(db); err != nil {
		return err
	}
	obs.ConditionID = obs.Condition.ID

	obs.Set = set
	if err := obs.Set.Insert(db, false); err != nil {
		return err
	}
	obs.SetID = obs.Set.ID

	return db.Insert(obs)
}

// Create tables. Use for testing and ptodb init command.
func CreateTables(db *pg.DB) error {
	opts := orm.CreateTableOptions{
		IfNotExists:   true,
		FKConstraints: true,
	}

	return db.RunInTransaction(func(tx *pg.Tx) error {
		if err := db.CreateTable(&Condition{}, &opts); err != nil {
			return err
		}

		if err := db.CreateTable(&Path{}, &opts); err != nil {
			return err
		}

		if err := db.CreateTable(&ObservationSet{}, &opts); err != nil {
			return err
		}

		if err := db.CreateTable(&Observation{}, &opts); err != nil {
			return err
		}

		return nil
	})
}

// Drop tables. Use only for testing, please.
func DropTables(db *pg.DB) error {
	return db.RunInTransaction(func(tx *pg.Tx) error {
		if err := db.DropTable(&Observation{}, nil); err != nil {
			return err
		}

		if err := db.DropTable(&ObservationSet{}, nil); err != nil {
			return err
		}

		if err := db.DropTable(&Condition{}, nil); err != nil {
			return err
		}

		if err := db.DropTable(&Path{}, nil); err != nil {
			return err
		}

		return nil
	})
}