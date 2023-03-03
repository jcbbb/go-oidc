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
)

func LoadViews() {
	Base = template.Must(template.ParseFS(ViewsFS, "views/login.html", "views/layout.html", "views/signup.html"))
	Signup, err = template.Must(Base.Clone()).ParseFS(ViewsFS, "views/signup.html", "views/layout.html")
	Login, err = template.Must(Base.Clone()).ParseFS(ViewsFS, "views/login.html", "views/layout.html")

	if err != nil {
		panic(err)
	}
}
