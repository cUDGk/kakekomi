package kakekomi

import (
	"embed"
	"html/template"
)

//go:embed templates/*.html
var tmplFS embed.FS

// loadTemplates parses layout.html + each page template into its own *Template.
// One *Template per page avoids "content" block name collisions.
func loadTemplates() map[string]*template.Template {
	pages := []string{"index", "submit", "done", "reply", "admin_inbox"}
	out := make(map[string]*template.Template, len(pages))
	for _, p := range pages {
		t := template.Must(template.ParseFS(tmplFS,
			"templates/layout.html",
			"templates/"+p+".html",
		))
		out[p] = t
	}
	return out
}
