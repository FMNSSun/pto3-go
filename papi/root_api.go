package papi

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	pto3 "github.com/mami-project/pto3-go"
)

type RootAPI struct {
	config *pto3.PTOConfiguration
}

func (ra *RootAPI) handleRoot(w http.ResponseWriter, r *http.Request) {

	links := make(map[string]string)

	links["banner"] = "This is an instance of the MAMI Path Transparency Observatory. See https://github.com/mami-project/pto3-go for more information."

	if ra.config.RawRoot != "" {
		links["raw"], _ = ra.config.LinkTo("raw")
	}

	if ra.config.ObsDatabase.Database != "" {
		links["obs"], _ = ra.config.LinkTo("obs")
	}

	if ra.config.QueryCacheRoot != "" {
		links["query"], _ = ra.config.LinkTo("query")
	}

	linksj, err := json.Marshal(links)

	if err != nil {
		pto3.HandleErrorHTTP(w, "marshaling root link list", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(linksj)
}

func (ra *RootAPI) addRoutes(r *mux.Router, l *log.Logger) {
	r.HandleFunc("/", LogAccess(l, ra.handleRoot)).Methods("GET")
}

func NewRootAPI(config *pto3.PTOConfiguration, azr Authorizer, r *mux.Router) *RootAPI {
	ra := new(RootAPI)
	ra.config = config
	ra.addRoutes(r, config.AccessLogger())
	return ra
}
