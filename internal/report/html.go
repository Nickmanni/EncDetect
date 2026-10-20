package report

import (
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"

	"encdetect/internal/detect"
)

var funcs = template.FuncMap{
	"size": detect.HumanSize,
	"num": func(n int64) string {
		s := fmt.Sprintf("%d", n)
		var b strings.Builder
		for i, c := range s {
			if i > 0 && (len(s)-i)%3 == 0 {
				b.WriteByte('.')
			}
			b.WriteRune(c)
		}
		return b.String()
	},
	"date":  func(t time.Time) string { return t.Local().Format("02.01.2006 15:04:05") },
	"pct":   func(f float64) string { return fmt.Sprintf("%.0f", f*100) },
	"f3":    func(f float64) string { return strings.Replace(fmt.Sprintf("%.3f", f), ".", ",", 1) },
	"label": func(s detect.Status) string { return s.Label() },
	"sub":   func(a, b int) int { return a - b },
}

var tpl = template.Must(template.New("r").Funcs(funcs).Parse(`<!doctype html>
<html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>EncDetect-Bericht – {{.FileName}}</title>
<style>
:root{--text:#182033;--muted:#5d6680;--line:#dde2ee;--bg:#f4f6fb;--card:#fff;
--encrypted:#d63c41;--clearkey:#d97a00;--partial:#e2600f;--suspected:#7f43b8;--plain:#23864f;--empty:#8a93a6;--unknown:#5f6985}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 "Segoe UI",system-ui,sans-serif}
.wrap{max-width:1000px;margin:0 auto;padding:28px 24px 50px}
h1{font-size:24px;margin:0}h2{font-size:17px;margin:0 0 6px}
.muted{color:var(--muted)}.mono{font-family:Consolas,ui-monospace,monospace;font-size:12.5px;word-break:break-all}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 20px;margin:14px 0}
.verdict{border-left:6px solid var(--c)}.verdict h2{color:var(--c);font-size:21px}
.encrypted{--c:var(--encrypted)}.clearkey{--c:var(--clearkey)}.partial{--c:var(--partial)}.suspected{--c:var(--suspected)}
.plain{--c:var(--plain)}.empty{--c:var(--empty)}.unknown{--c:var(--unknown)}
.badge{display:inline-block;font-size:12px;font-weight:700;padding:2px 10px;border-radius:99px;color:#fff;background:var(--c);vertical-align:middle}
table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:4px 10px 4px 0;vertical-align:top;border-bottom:1px solid var(--line)}
th{color:var(--muted);font-weight:500;width:34%}
.vol{border-left:5px solid var(--c)}.vol h2 span{font-weight:400}
.sub{margin:10px 0 0;padding:8px 12px;border:1px solid var(--line);border-left:4px solid var(--c);border-radius:8px}
ul.notes{margin:10px 0 0;padding-left:18px}ul.notes li{margin:3px 0}
.head{display:flex;justify-content:space-between;align-items:flex-end;gap:20px;border-bottom:2px solid var(--text);padding-bottom:10px}
footer{margin-top:24px;font-size:12px;color:var(--muted)}
@media print{body{background:#fff}.card{break-inside:avoid;border-color:#bbb}.wrap{padding:0}}
</style></head><body><div class="wrap">
<div class="head">
 <div><h1>Analysebericht Verschlüsselung</h1><div class="muted">EncDetect {{.Version}}</div></div>
 <div class="muted" style="text-align:right">Erstellt: {{date .Started}}<br>Dauer: {{.DurationMs}} ms</div>
</div>

<div class="card verdict {{.Overall}}">
 <h2>{{.OverallText}}</h2>
 <div>{{.OverallSummary}}</div>
</div>

<div class="card">
 <h2>Image</h2>
 <table>
  <tr><th>Datei</th><td class="mono">{{.Path}}</td></tr>
  <tr><th>Format</th><td>{{.Format}}</td></tr>
  <tr><th>Größe</th><td>{{size .Size}} ({{num .Size}} Bytes)</td></tr>
  <tr><th>Partitionsschema</th><td>{{.PartitionScheme}}</td></tr>
  {{range .Meta}}{{if ne .Key "Datei"}}<tr><th>{{.Key}}</th><td>{{.Value}}</td></tr>{{end}}{{end}}
 </table>
 {{range .DiskNotes}}<p>⚑ {{.}}</p>{{end}}
 {{range .Warnings}}<p>⚠ {{.}}</p>{{end}}
</div>

<div class="card">
 <h2>Übersicht</h2>
 <table>
  <tr><th style="width:auto">#</th><th style="width:auto">Offset</th><th style="width:auto">Größe</th><th style="width:auto">Typ</th><th style="width:auto">Ergebnis</th><th style="width:auto">Verfahren / Algorithmus</th></tr>
  {{range .Volumes}}<tr class="{{.Status}}"><td>{{.Index}}</td><td class="mono" style="white-space:nowrap">{{num .Offset}}</td><td>{{size .Size}}</td><td>{{.PartType}}</td>
  <td><span class="badge">{{.StatusText}}</span></td><td>{{.Scheme}}{{if .Algorithm}}<br><span class="muted">{{.Algorithm}}</span>{{end}}</td></tr>{{end}}
 </table>
</div>

{{range .Volumes}}
<div class="card vol {{.Status}}">
 <h2>{{.Label}}{{if .PartName}} <span>„{{.PartName}}“</span>{{end}} – {{.Scheme}} <span class="badge">{{.StatusText}}</span></h2>
 <p>{{.Summary}}</p>
 <table>
  <tr><th>Offset</th><td>{{num .Offset}} Bytes</td></tr>
  <tr><th>Größe</th><td>{{size .Size}} ({{num .Size}} Bytes)</td></tr>
  <tr><th>Partitionstyp</th><td>{{.PartType}}</td></tr>
  {{if .Algorithm}}<tr><th>Algorithmus</th><td><b>{{.Algorithm}}</b></td></tr>{{end}}
  <tr><th>Konfidenz</th><td>{{.Confidence}} %</td></tr>
  {{range .Details}}<tr><th>{{.Key}}</th><td{{if or (eq .Key "FVEK (Hex)") (eq .Key "Volume-GUID")}} class="mono"{{end}}>{{.Value}}</td></tr>{{end}}
  {{with .Entropy}}<tr><th>Entropie</th><td>Ø {{f3 .AvgEntropy}} Bit/Byte · {{.RandomBlocks}} von {{sub .Samples .ZeroBlocks}} Datenstichproben zufällig ({{pct .RandomFraction}} %) · {{.ZeroBlocks}} leer</td></tr>{{end}}
 </table>
 {{range .Sub}}<div class="sub {{.Status}}"><b>{{.Name}}</b> <span class="badge">{{label .Status}}</span><div>{{.Summary}}</div>
  {{if .Details}}<table>{{range .Details}}<tr><th>{{.Key}}</th><td>{{.Value}}</td></tr>{{end}}</table>{{end}}</div>{{end}}
 {{if .Notes}}<ul class="notes">{{range .Notes}}<li>{{.}}</li>{{end}}</ul>{{end}}
</div>
{{end}}

<footer>Das Image wurde ausschließlich lesend geöffnet. Statistische Aussagen („vermutlich verschlüsselt“) beruhen auf Entropie- und Chi-Quadrat-Tests und sind kein Beweis; sicher mit Zufallsdaten überschriebene oder stark komprimierte Bereiche können ähnlich aussehen.</footer>
</div></body></html>`))

func HTML(w io.Writer, r *detect.Report) error {
	return tpl.Execute(w, r)
}
