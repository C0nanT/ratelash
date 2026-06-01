package webui

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite" // register sqlite driver
)

type fuzzRouteRow struct {
	Path          string         `json:"path"`
	Statuses      map[string]int `json:"statuses"`
	TotalHits     int            `json:"total_hits"`
	Has2xx        bool           `json:"has2xx"`
	PrimaryStatus int            `json:"primary_status"`
}

type fuzzPageResult struct {
	Rows              []fuzzRouteRow `json:"rows"`
	Total             int            `json:"total"`
	Found2xx          int            `json:"found_2xx"`
	Page              int            `json:"page"`
	PerPage           int            `json:"per_page"`
	TotalPages        int            `json:"total_pages"`
	AvailableStatuses []int          `json:"available_statuses"`
}

type queryOpts struct {
	SortBy       string // "hits", "status", "path"
	SortOrder    string // "asc", "desc"
	FilterStatus []int
}

type fuzzDB struct {
	db *sql.DB
}

var globalFuzzDB *fuzzDB
var runCounter int64

// FuzzDBPath is the file used for temporary fuzz results storage.
var FuzzDBPath string

func openFuzzDB() error {
	FuzzDBPath = filepath.Join(os.TempDir(), "limithit-fuzz.db")
	db, err := sql.Open("sqlite", FuzzDBPath)
	if err != nil {
		return fmt.Errorf("open fuzz db: %w", err)
	}
	db.SetMaxOpenConns(1)

	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS fuzz_routes (
			run_id         TEXT    NOT NULL,
			path           TEXT    NOT NULL,
			statuses       TEXT    NOT NULL,
			total_hits     INTEGER NOT NULL,
			has2xx         INTEGER NOT NULL DEFAULT 0,
			primary_status INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_fuzz_run ON fuzz_routes(run_id)`,
		`CREATE TABLE IF NOT EXISTS fuzz_route_statuses (
			run_id      TEXT    NOT NULL,
			path        TEXT    NOT NULL,
			status_code INTEGER NOT NULL,
			hits        INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_fuzz_sc ON fuzz_route_statuses(run_id, status_code)`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("init schema: %w", err)
		}
	}
	globalFuzzDB = &fuzzDB{db: db}
	return nil
}

func (s *fuzzDB) clearDB() error {
	if _, err := s.db.Exec(`DELETE FROM fuzz_routes`); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM fuzz_route_statuses`)
	return err
}

func newRunID() string {
	n := atomic.AddInt64(&runCounter, 1)
	return fmt.Sprintf("%d_%d", time.Now().UnixNano(), n)
}

func (s *fuzzDB) saveRoutes(runID string, pathStatus map[string]map[int]int) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}

	routeStmt, err := tx.Prepare(`INSERT INTO fuzz_routes(run_id, path, statuses, total_hits, has2xx, primary_status) VALUES (?,?,?,?,?,?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer routeStmt.Close()

	scStmt, err := tx.Prepare(`INSERT INTO fuzz_route_statuses(run_id, path, status_code, hits) VALUES (?,?,?,?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer scStmt.Close()

	for path, statusMap := range pathStatus {
		total := 0
		has2xx := 0
		primaryStatus := 0
		maxHits := -1
		strStatuses := make(map[string]int, len(statusMap))

		for code, cnt := range statusMap {
			total += cnt
			strStatuses[fmt.Sprintf("%d", code)] = cnt
			if code >= 200 && code < 300 {
				has2xx = 1
			}
			if cnt > maxHits {
				maxHits = cnt
				primaryStatus = code
			}
		}

		data, _ := json.Marshal(strStatuses)
		if _, err := routeStmt.Exec(runID, path, string(data), total, has2xx, primaryStatus); err != nil {
			_ = tx.Rollback()
			return err
		}
		for code, cnt := range statusMap {
			if _, err := scStmt.Exec(runID, path, code, cnt); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
	}
	return tx.Commit()
}

func (s *fuzzDB) queryRoutes(runID string, page, perPage int, opts queryOpts) (fuzzPageResult, error) {
	// ORDER BY
	sortDir := "DESC"
	if opts.SortOrder == "asc" {
		sortDir = "ASC"
	}
	var orderClause string
	switch opts.SortBy {
	case "status":
		orderClause = fmt.Sprintf("r.primary_status %s, r.total_hits DESC", sortDir)
	case "path":
		orderClause = fmt.Sprintf("r.path %s", sortDir)
	default: // "hits"
		orderClause = fmt.Sprintf("r.has2xx DESC, r.total_hits %s", sortDir)
	}

	// Filter subquery
	filterClause := ""
	baseArgs := []interface{}{runID}
	if len(opts.FilterStatus) > 0 {
		ph := strings.TrimSuffix(strings.Repeat("?,", len(opts.FilterStatus)), ",")
		filterClause = fmt.Sprintf(` AND EXISTS (
			SELECT 1 FROM fuzz_route_statuses s
			WHERE s.run_id = r.run_id AND s.path = r.path AND s.status_code IN (%s)
		)`, ph)
		for _, sc := range opts.FilterStatus {
			baseArgs = append(baseArgs, sc)
		}
	}

	where := fmt.Sprintf("r.run_id=?%s", filterClause)
	where2xx := fmt.Sprintf("r.run_id=? AND r.has2xx=1%s", filterClause)

	var total, found2xx int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM fuzz_routes r WHERE "+where, baseArgs...).Scan(&total); err != nil {
		return fuzzPageResult{}, err
	}
	if err := s.db.QueryRow("SELECT COUNT(*) FROM fuzz_routes r WHERE "+where2xx, baseArgs...).Scan(&found2xx); err != nil {
		return fuzzPageResult{}, err
	}

	offset := (page - 1) * perPage
	pageArgs := append(append([]interface{}{}, baseArgs...), perPage, offset)
	rows, err := s.db.Query(fmt.Sprintf(`
		SELECT r.path, r.statuses, r.total_hits, r.has2xx, r.primary_status
		FROM fuzz_routes r
		WHERE %s
		ORDER BY %s
		LIMIT ? OFFSET ?`, where, orderClause), pageArgs...)
	if err != nil {
		return fuzzPageResult{}, err
	}
	defer rows.Close()

	result := make([]fuzzRouteRow, 0, perPage)
	for rows.Next() {
		var row fuzzRouteRow
		var statusesJSON string
		var has2xxInt int
		if err := rows.Scan(&row.Path, &statusesJSON, &row.TotalHits, &has2xxInt, &row.PrimaryStatus); err != nil {
			return fuzzPageResult{}, err
		}
		row.Has2xx = has2xxInt == 1
		if err := json.Unmarshal([]byte(statusesJSON), &row.Statuses); err != nil {
			row.Statuses = map[string]int{}
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return fuzzPageResult{}, err
	}

	available, _ := s.queryAvailableStatuses(runID)

	totalPages := (total + perPage - 1) / perPage
	if totalPages < 1 {
		totalPages = 1
	}
	return fuzzPageResult{
		Rows:              result,
		Total:             total,
		Found2xx:          found2xx,
		Page:              page,
		PerPage:           perPage,
		TotalPages:        totalPages,
		AvailableStatuses: available,
	}, nil
}

func (s *fuzzDB) queryAvailableStatuses(runID string) ([]int, error) {
	rows, err := s.db.Query(`SELECT DISTINCT status_code FROM fuzz_route_statuses WHERE run_id=? ORDER BY status_code`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int
	for rows.Next() {
		var sc int
		if err := rows.Scan(&sc); err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}
