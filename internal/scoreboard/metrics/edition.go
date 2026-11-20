package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// EditionNone is the run_id of scoreboard_edition_loaded_info for a scoreboard
// assembled without an answers table: no investigate challenge in scope, so none is
// needed (ADR-0056 A4f). The contract table's row "scoreboard の edition の読み込みの
// metric" names it, and internal/contractmetrics holds the row to this constant.
const EditionNone = "none"

// editionLoadedGauge is scoreboard_edition_loaded_info{run_id} (ADR-0056 A4f, V105;
// ADR-0040's info kind): the generation of the answers table this scoreboard
// loaded, as a gauge whose one series is always 1. run_id is the table's run id (32
// lower-case hex digits; 32 zeros = the practice edition) or EditionNone. It never
// carries a table value, a seat or a challenge: the run id is not an answer, and no
// answer can be derived from it.
//
// It has no series until the scoreboard is assembled (ADR-0040's info kind (3): the
// family is absent before the assembly and present after it), and from then on
// EXACTLY one: set replaces the series under lock (Reset, then the one child), so a
// second assembly in the same process (the tests assemble many handlers on the
// default registry) leaves the series of the last one, never two. Production
// assembles once, so the series does not change for the life of the Pod.
type editionLoadedGauge struct {
	lock   sync.Mutex // makes Reset and the one Set a single step for concurrent setters
	series *prometheus.GaugeVec
}

func newEditionLoadedGauge(reg prometheus.Registerer) *editionLoadedGauge {
	return &editionLoadedGauge{series: promauto.With(reg).NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "scoreboard",
		Name:      "edition_loaded_info",
		Help:      "The answers table this scoreboard loaded at start: run_id is its run id (32 lower-case hex digits, 32 zeros for the practice edition) or none (no table needed). Always 1, exactly one series.",
	}, []string{"run_id"})}
}

// set makes runID the one series, at 1.
func (g *editionLoadedGauge) set(runID string) {
	g.lock.Lock()
	defer g.lock.Unlock()
	g.series.Reset()
	g.series.WithLabelValues(runID).Set(1)
}

var editionLoaded = newEditionLoadedGauge(prometheus.DefaultRegisterer)

// SetEditionLoaded makes runID the one series of scoreboard_edition_loaded_info. Its
// one caller is scoreboard.NewHandler (the assembly that internal/contractmetrics
// runs as production does), which derives runID from the Judge and the run id that
// edition.Load returned: a run id only when a Judge is wired, else EditionNone.
func SetEditionLoaded(runID string) { editionLoaded.set(runID) }
