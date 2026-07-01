// Command docsgen renders the Markdown files in docs/ into standalone HTML pages
// that share the landing page's look, plus a docs.html catalog. It runs in the
// Pages CI job, so the published docs never drift from their Markdown source.
//
// It lives in its own module on purpose: goldmark stays out of arca's
// dependency-light main go.mod (and its release binary + SBOM).
package main

import (
	"bytes"
	"flag"
	"fmt"
	"html"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	gmhtml "github.com/yuin/goldmark/renderer/html"
	"github.com/yuin/goldmark/text"
)

// repoBlob is where non-docs Markdown links (../README.md, ../SECURITY.md) resolve to.
const repoBlob = "https://github.com/arenzana/arca/blob/main/"

// order is the preferred reading order for the catalog; unlisted docs are appended
// alphabetically so a new .md still shows up without touching this file.
var order = []string{
	"COMMANDS", "CONFIGURATION", "POLICIES", "IMPORTING", "MCP", "ARCHITECTURE", "THREAT-MODEL",
}

type page struct {
	slug  string // file base without extension, e.g. "COMMANDS"
	title string // from the first H1
	blurb string // first real paragraph, for the catalog
}

func main() {
	root := flag.String("root", ".", "repository root (the dir containing docs/)")
	flag.Parse()

	docsDir := filepath.Join(*root, "docs")
	mds, err := filepath.Glob(filepath.Join(docsDir, "*.md"))
	if err != nil {
		log.Fatalf("glob: %v", err)
	}
	if len(mds) == 0 {
		log.Fatalf("no *.md found in %s", docsDir)
	}

	md := goldmark.New(
		goldmark.WithExtensions(extension.GFM),
		goldmark.WithParserOptions(parser.WithAutoHeadingID()),
		goldmark.WithRendererOptions(gmhtml.WithUnsafe()),
	)

	var pages []page
	for _, mdPath := range mds {
		p, err := renderFile(md, docsDir, mdPath)
		if err != nil {
			log.Fatalf("%s: %v", mdPath, err)
		}
		pages = append(pages, p)
		fmt.Printf("rendered %s.html\n", p.slug)
	}

	if err := writeCatalog(docsDir, pages); err != nil {
		log.Fatalf("catalog: %v", err)
	}
	fmt.Println("rendered docs.html")
}

func renderFile(md goldmark.Markdown, docsDir, mdPath string) (page, error) {
	src, err := os.ReadFile(mdPath)
	if err != nil {
		return page{}, err
	}
	slug := strings.TrimSuffix(filepath.Base(mdPath), ".md")

	node := md.Parser().Parse(text.NewReader(src))
	rewriteLinks(node)
	title, blurb := meta(node, src, slug)

	var body bytes.Buffer
	if err := md.Renderer().Render(&body, src, node); err != nil {
		return page{}, err
	}

	content := fmt.Sprintf(`  <div class="doc">
    <a class="backlink" href="docs.html">← All docs</a>
    <article>%s</article>
  </div>`, body.String())

	out := shell(title+" · arca", content)
	if err := os.WriteFile(filepath.Join(docsDir, slug+".html"), []byte(out), 0o644); err != nil {
		return page{}, err
	}
	return page{slug: slug, title: title, blurb: blurb}, nil
}

// rewriteLinks turns Markdown cross-links into working HTML links: sibling FOO.md
// → FOO.html, and anything with a path (../README.md) → the GitHub blob.
func rewriteLinks(node ast.Node) {
	_ = ast.Walk(node, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		link, ok := n.(*ast.Link)
		if !ok {
			return ast.WalkContinue, nil
		}
		dest := string(link.Destination)
		path, frag, _ := strings.Cut(dest, "#")
		if !strings.HasSuffix(path, ".md") {
			return ast.WalkContinue, nil
		}
		if strings.Contains(path, "/") {
			rel := path
			for strings.HasPrefix(rel, "../") {
				rel = strings.TrimPrefix(rel, "../")
			}
			path = repoBlob + rel
		} else {
			path = strings.TrimSuffix(path, ".md") + ".html"
		}
		if frag != "" {
			path += "#" + frag
		}
		link.Destination = []byte(path)
		return ast.WalkContinue, nil
	})
}

// meta extracts the H1 title and a catalog blurb (first paragraph that isn't a
// breadcrumb line). Falls back to the slug and an empty blurb.
func meta(node ast.Node, src []byte, slug string) (title, blurb string) {
	title = slug
	for c := node.FirstChild(); c != nil; c = c.NextSibling() {
		if h, ok := c.(*ast.Heading); ok && h.Level == 1 && title == slug {
			title = nodeText(h, src)
			continue
		}
		if p, ok := c.(*ast.Paragraph); ok && blurb == "" {
			t := strings.TrimSpace(nodeText(p, src))
			if t == "" || strings.HasPrefix(t, "←") || strings.Contains(t, "related:") {
				continue
			}
			blurb = truncate(t, 200)
		}
	}
	return title, blurb
}

func nodeText(n ast.Node, src []byte) string {
	var b strings.Builder
	_ = ast.Walk(n, func(c ast.Node, entering bool) (ast.WalkStatus, error) {
		if entering {
			if t, ok := c.(*ast.Text); ok {
				b.Write(t.Segment.Value(src))
			}
		}
		return ast.WalkContinue, nil
	})
	return strings.TrimSpace(b.String())
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := s[:n]
	if i := strings.LastIndex(cut, " "); i > 0 {
		cut = cut[:i]
	}
	return cut + "…"
}

func writeCatalog(docsDir string, pages []page) error {
	rank := map[string]int{}
	for i, s := range order {
		rank[s] = i
	}
	sort.SliceStable(pages, func(i, j int) bool {
		ri, oki := rank[pages[i].slug]
		rj, okj := rank[pages[j].slug]
		switch {
		case oki && okj:
			return ri < rj
		case oki != okj:
			return oki // ranked docs before unranked
		default:
			return pages[i].slug < pages[j].slug
		}
	})

	var cards strings.Builder
	for _, p := range pages {
		cards.WriteString(fmt.Sprintf(`    <a class="card" href="%s.html">
      <h3>%s</h3>
      <p>%s</p>
    </a>
`, p.slug, html.EscapeString(p.title), html.EscapeString(p.blurb)))
	}

	content := fmt.Sprintf(`  <header class="doc-hero">
    <div class="wrap">
      <div class="eyebrow">documentation</div>
      <h1>arca docs</h1>
      <p class="tagline">Guides and reference for the age-encrypted, agent-safe secrets manager.</p>
    </div>
  </header>
  <section class="wrap">
    <div class="grid catalog">
%s    </div>
  </section>`, cards.String())

	return os.WriteFile(filepath.Join(docsDir, "docs.html"), []byte(shell("Documentation · arca", content)), 0o644)
}
