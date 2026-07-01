package main

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"golang.org/x/term"
)

// arca's brand palette, reused from the logo/website.
var (
	tealColor  = lipgloss.Color("#3FA39B")
	coralColor = lipgloss.Color("#EC8B77")
	greenColor = lipgloss.Color("#5FB49C")
	amberColor = lipgloss.Color("#E9C26B")
)

func stdoutIsTTY() bool { return term.IsTerminal(int(os.Stdout.Fd())) }

// renderTable prints a styled, bordered table on a terminal, or plain tab-separated columns when
// the output is piped — so scripts and grep still get clean, parseable rows. Cells may already be
// styled (see colorOp); lipgloss measures ANSI-aware, so columns stay aligned.
func renderTable(headers []string, rows [][]string) {
	if !stdoutIsTTY() {
		plainTable(headers, rows)
		return
	}
	fmt.Println(styledTable(headers, rows))
}

// styledTable renders a bordered, teal-headed lipgloss table. Split out from the TTY check so it's
// directly testable.
func styledTable(headers []string, rows [][]string) string {
	return table.New().
		Border(lipgloss.RoundedBorder()).
		BorderStyle(lipgloss.NewStyle().Foreground(tealColor)).
		Headers(headers...).
		Rows(rows...).
		StyleFunc(func(row, _ int) lipgloss.Style {
			s := lipgloss.NewStyle().Padding(0, 1)
			if row == table.HeaderRow {
				return s.Foreground(tealColor).Bold(true)
			}
			return s
		}).
		Render()
}

func plainTable(headers []string, rows [][]string) {
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	defer w.Flush()
	fmt.Fprintln(w, strings.Join(headers, "\t"))
	for _, r := range rows {
		fmt.Fprintln(w, strings.Join(r, "\t"))
	}
}

// colorOp tints an audit op for the styled table — green for a use, amber for a write, coral for
// an alert or removal. It returns the plain op when stdout isn't a terminal, so piped output stays
// unstyled.
func colorOp(op string) string {
	if !stdoutIsTTY() {
		return op
	}
	return styledOp(op)
}

func styledOp(op string) string {
	var c lipgloss.Color
	switch op {
	case "read", "exec", "env", "inject":
		c = greenColor
	case "set", "rotate", "generate", "import", "grant", "handle-create":
		c = amberColor
	case "canary", "ratelimit", "redact", "rm", "revoke", "handle-revoke":
		c = coralColor
	default:
		c = tealColor
	}
	return lipgloss.NewStyle().Foreground(c).Render(op)
}
