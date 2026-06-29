// Shell completion helpers. Cobra already provides the `completion` command that emits
// bash/zsh/fish/powershell scripts; these functions add *dynamic* completion so that, with that
// script sourced, `arca get <TAB>` offers the actual secret names and `arca ls --tag <TAB>` the
// tags in the store. Completion runs the binary, so it reads the live store on every TAB.
package main

import (
	"strings"

	"github.com/spf13/cobra"
)

// completeSecretNames offers secret names not already present in args, filtered by the partial
// word being typed. Used for NAME arguments and for `exec --only`.
func completeSecretNames(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	s, err := openStore()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var out []string
	for _, name := range s.Names() {
		if strings.HasPrefix(name, toComplete) && !contains(args, name) {
			out = append(out, name)
		}
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}

// completeTags offers the distinct tags currently in use, filtered by the partial word.
func completeTags(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	s, err := openStore()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	seen := map[string]bool{}
	var out []string
	for _, name := range s.Names() {
		for _, tag := range s.Secrets[name].Tags {
			if !seen[tag] && strings.HasPrefix(tag, toComplete) {
				seen[tag] = true
				out = append(out, tag)
			}
		}
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}

// registerCompletions wires dynamic completion onto the commands that take a secret NAME or a
// secret/tag-valued flag.
func registerCompletions(cmds []*cobra.Command) {
	for _, c := range cmds {
		switch c.Name() {
		case "get", "show", "rm", "rotate":
			c.ValidArgsFunction = completeSecretNames
		case "exec":
			_ = c.RegisterFlagCompletionFunc("only", completeSecretNames)
		case "ls":
			_ = c.RegisterFlagCompletionFunc("tag", completeTags)
		case "set":
			_ = c.RegisterFlagCompletionFunc("tag", completeTags)
		}
	}
}
