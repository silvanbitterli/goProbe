/////////////////////////////////////////////////////////////////////////////////
//
// conditional.go
//
// Written by Lorenz Breidenbach lob@open.ch, February 2016
// Copyright (c) 2016 Open Systems AG, Switzerland
// All Rights Reserved.
//
/////////////////////////////////////////////////////////////////////////////////

package main

import (
	"fmt"
	"github.com/els0r/goProbe/pkg/goDB/conditions/node"
	"strings"

	"github.com/els0r/goProbe/pkg/goDB/conditions"
	"github.com/els0r/goProbe/pkg/goDB/protocols"
	"github.com/els0r/goProbe/pkg/types"
)

//var dirKeywordOccurred = false
//var topLevelAnd = false
//var dirKeywordDisallowed = false

func openParens(tokens []string) int {
	open := 0
	for _, token := range tokens {
		switch token {
		case "(":
			open++
		case ")":
			open--
		}
	}
	return open
}

func nextAll(prevprev, prev string, openParens int) []suggestion {
	s := func(sugg string, accept bool) suggestion {
		if accept {
			return suggestion{sugg, sugg, accept}
		}
		return suggestion{sugg, sugg + " ...  ", accept}
	}
	fmt.Println(prevprev, prev)
	switch prev {
	case "", "(", "&", "|":
		suggs := []suggestion{
			s("!", false),
			s("(", false),
			s(types.DIPName, false),
			s(types.SIPName, false),
			s("dnet", false),
			s("snet", false),
			s("dst", false),
			s("src", false),
			s("host", false),
			s("net", false),
			s(types.DportName, false),
			s("port", false),
			s(types.ProtoName, false),
			s(node.FilterKeywordDirection, false)}

		/*
			// suggest direction filter in case condition is still
			if prev == "" {
				suggs = append(suggs, s(node.FilterKeywordDirection, false))
			}

			// suggest direction filter if (1) the position is directly
			// after a top-level conjunction, and (2) no direction filter
			// was previously specified.
			if prev == "&" && topLevelAnd && !dirKeywordOccurred {
				suggs = append(suggs, s(node.FilterKeywordDirection, false))
			}
		*/
		return suggs

	case "!":
		return []suggestion{
			s("(", false),
			s(types.DIPName, false),
			s(types.SIPName, false),
			s("dnet", false),
			s("snet", false),
			s("dst", false),
			s("src", false),
			s("host", false),
			s("net", false),
			s(types.DportName, false),
			s("port", false),
			s(types.ProtoName, false),
		}
	case types.DIPName, types.SIPName, "dnet", "snet", "dst", "src", "host", "net":
		return []suggestion{
			s("=", false),
			s("!=", false),
		}
	case types.DportName, "port", types.ProtoName:
		return []suggestion{
			s("=", false),
			s("!=", false),
			s("<", false),
			s(">", false),
			s("<=", false),
			s(">=", false),
		}
	case node.FilterKeywordDirection:
		return []suggestion{
			s("=", false),
		}
	case "=", "!=", "<", ">", "<=", ">=":
		switch prevprev {
		case types.ProtoName:
			var result []suggestion
			for name := range protocols.IPProtocolIDs {
				result = append(result, suggestion{name, name + " ...", openParens == 0})
			}
			return result
		case node.FilterKeywordDirection:
			return []suggestion{
				s(string(node.FilterTypeDirectionIn), openParens == 0),
				s(string(node.FilterTypeDirectionOut), openParens == 0),
				s(string(node.FilterTypeDirectionUni), openParens == 0),
				s(string(node.FilterTypeDirectionBi), openParens == 0),
			}
		default:
			return nil
		}
	case ")":
		if openParens > 0 {
			return []suggestion{
				s(")", openParens == 1),
				s("&", false),
				s("|", false),
			}
		}
		return []suggestion{
			s("&", false),
			s("|", false),
		}
	default:
		switch prevprev {
		case "=", "!=", "<", ">", "<=", ">=":
			if openParens > 0 {
				return []suggestion{
					s(")", openParens == 1),
					s("&", false),
					s("|", false),
				}
			}
			return []suggestion{
				s("&", false),
				s("|", false),
			}
		default:
			return nil
		}
	}
}

func conditional(args []string) []string {
	tokenize := func(conditional string) []string {
		san, err := conditions.SanitizeUserInput(conditional)
		if err != nil {
			return nil
		}
		tokens, err := conditions.Tokenize(san)
		if err != nil {
			return nil
		}

		if startedNewToken := len(tokens) == 0 || strings.LastIndex(conditional, tokens[len(tokens)-1])+len(tokens[len(tokens)-1]) < len(conditional); startedNewToken {
			tokens = append(tokens, "")
		}

		return tokens
	}

	join := func(tokens []string) string {
		return strings.Join(tokens, " ")
	}

	next := func(tokens []string) suggestions {
		var suggs []suggestion

		// check whether the direction filter keyword
		// has already occurred in the condition
		dirKeywordOccurred := false
		for _, token := range tokens {
			if token == node.FilterKeywordDirection {
				dirKeywordOccurred = true
			}
		}

		// get position of first top-level binary operator
		var firstTopLevelBinaryOpPos = 0
		for i, token := range tokens {
			if (token == "&" || token == "|") && openParens(tokens[:i]) == 0 {
				firstTopLevelBinaryOpPos = i
				break
			}
		}

		// check if first top-level binary operator is a conjunction
		topLevelAnd := tokens[firstTopLevelBinaryOpPos] == "&" && firstTopLevelBinaryOpPos == len(tokens)-2

		prevprev := antepenultimate(tokens)
		prev := penultimate(tokens)
		for _, sugg := range nextAll(prevprev, prev, openParens(tokens)) {
			if strings.HasPrefix(sugg.token, last(tokens)) {
				if strings.Contains(sugg.token, node.FilterKeywordDirection) {
					if !(prev == "" || (topLevelAnd && !dirKeywordOccurred)) {
						continue
					}
				}
				suggs = append(suggs, sugg)
			}
		}
		if len(suggs) == 0 {
			return unknownSuggestions{}
		}
		return knownSuggestions{suggs}
	}

	unknown := func(s string) []string {
		return []string{s, " (I can't help you)"}
	}

	return complete(tokenize, join, next, unknown, last(args))
}
