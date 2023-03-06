package views

import (
	"embed"
	"html/template"
)

var (
	ViewsFS embed.FS
	err     error
	Base    *template.Template
	Signup  *template.Template
	Login   *template.Template
	Consent *template.Template
	Error   *template.Template
)

func LoadViews() {
	funcs := template.FuncMap{
		"deref": func(i *int) int { return *i },
	}

	Base = template.Must(template.New("").Funcs(funcs).ParseFS(ViewsFS, "views/login.html", "views/layout.html", "views/signup.html"))
	Signup, err = template.Must(Base.Clone()).ParseFS(ViewsFS, "views/signup.html", "views/layout.html")
	Login, err = template.Must(Base.Clone()).ParseFS(ViewsFS, "views/login.html", "views/layout.html")
	Consent, err = template.Must(Base.Clone()).ParseFS(ViewsFS, "views/consent.html", "views/layout.html")
	Error, err = template.Must(Base.Clone()).ParseFS(ViewsFS, "views/error.html", "views/layout.html")

	if err != nil {
		panic(err)
	}
}
