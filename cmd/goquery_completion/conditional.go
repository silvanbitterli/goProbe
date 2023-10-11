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
	"strings"

	"github.com/els0r/goProbe/pkg/goDB/conditions"
	"github.com/els0r/goProbe/pkg/goDB/protocols"
	"github.com/els0r/goProbe/pkg/types"
)

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

// dirKeywordOccurrences counts the number of dir keyword occurrences
// in tokens
func dirKeywordOccurrences(tokens []string) int {
	dirKeywordOccurrences := 0
	for _, token := range tokens {
		if token == types.FilterKeywordDirection || token == types.FilterKeywordDirectionSugared {
			dirKeywordOccurrences++
		}
	}
	return dirKeywordOccurrences
}

// firstTopLevelBinaryOp returns the position of the first
// top-level binary logical operator inside tokens and the respective token.
// It returns -1 and an empty string if tokens do not contain any binary logical operator.
func firstTopLevelBinaryOp(tokens []string) (int, string) {
	for i, token := range tokens {
		if (token == "&" || token == "|") && openParens(tokens[:i]) == 0 {
			return i, token
		}
	}
	return -1, ""
}

func nextAll(prevprev, prev string, openParens int) []suggestion {
	s := func(sugg string, accept bool) suggestion {
		if accept {
			return suggestion{sugg, sugg, accept}
		}
		return suggestion{sugg, sugg + " ...  ", accept}
	}

	switch prev {
	case "", "(", "&", "|":
		return []suggestion{
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
			s(types.FilterKeywordDirection, false),
			s(types.FilterKeywordDirectionSugared, false),
		}
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
	case types.FilterKeywordDirection, types.FilterKeywordDirectionSugared:
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
		case types.FilterKeywordDirection, types.FilterKeywordDirectionSugared:
			var result []suggestion
			for _, direction := range types.DirectionFilters {
				result = append(result, s(string(direction), true))
			}
			return result
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
	case string(types.FilterTypeDirectionIn), string(types.FilterTypeDirectionOut),
		string(types.FilterTypeDirectionUni), string(types.FilterTypeDirectionBi),
		string(types.FilterTypeDirectionInSugared), string(types.FilterTypeDirectionOutSugared),
		string(types.FilterTypeDirectionUniSugared), string(types.FilterTypeDirectionBiSugared):
		return []suggestion{
			s("&", false),
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
		prevprev := antepenultimate(tokens)
		prev := penultimate(tokens)
		openParens := openParens(tokens)
		last := last(tokens)
		dirKeywordOccurrences := dirKeywordOccurrences(tokens[:len(tokens)-1])
		for _, sugg := range nextAll(prevprev, prev, openParens) {
			if strings.HasPrefix(sugg.token, last) {
				// check if suggestion is valid based on the current condition string
				if verifySuggestion(tokens, sugg, prevprev, prev, openParens, dirKeywordOccurrences) {
					suggs = append(suggs, sugg)
				}
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

// verifySuggestion enforces some structural constraints on the condition,
// only if the current suggestion is the dir keyword, or the dir keyword
// has already appeared, ensuring that the dir keyword only occurs at valid places.
func verifySuggestion(tokens []string, sugg suggestion, prevprev string, prev string, openParens, dirKeywordOccurrences int) bool {
	if strings.Contains(sugg.token, types.FilterKeywordDirection) ||
		strings.Contains(sugg.token, types.FilterKeywordDirectionSugared) ||
		dirKeywordOccurrences > 0 {
		firstTopLevelBinaryOpPos, firstTopLevelBinaryOp := firstTopLevelBinaryOp(tokens)
		// filter out suggestions that invalidate the dir keyword
		if !checkDirKeywordConstraints(sugg, prevprev, prev, len(tokens), openParens,
			dirKeywordOccurrences, firstTopLevelBinaryOpPos, firstTopLevelBinaryOp) {
			return false
		}
	}
	return true
}

// checkDirKeywordConstraints checks whether sugg is a valid suggestion with respect to the
// constraints on the structure of the condition introduced by the dir keyword.
// checkDirKeywordConstraints returns true if sugg is a valid suggestion and false otherwise.
func checkDirKeywordConstraints(sugg suggestion, prevprev, prev string,
	nTokens, openParens, dirKeywordOccurrences, firstTopLevelBinaryOpPos int, firstTopLevelBinaryOp string) bool {

	// determine whether prev is a top-level conjunction
	topLevelAnd := firstTopLevelBinaryOp == "&" && firstTopLevelBinaryOpPos == nTokens-2
	// determine whether a top-level conjunction has previously occurred
	topLevelAndOccurred := firstTopLevelBinaryOp == "&" && firstTopLevelBinaryOpPos <= nTokens-2

	// if there is already more than one dir keyword occurrence, the condition is invalid
	// no matter what comes afterwards
	if dirKeywordOccurrences > 1 {
		return false
	}

	// the dir keyword must only be suggested at the start of the condition (condition currently empty)
	// or directly after a top-level conjunction
	if !strings.Contains(sugg.token, "directional") &&
		(strings.Contains(sugg.token, types.FilterKeywordDirection) || strings.Contains(sugg.token, types.FilterKeywordDirectionSugared)) {
		if !(prev == "" || (topLevelAnd && dirKeywordOccurrences == 0)) {
			return false
		}
	}

	// if the top-level binary operator is not a conjunction, the dir keyword must not be used as the right
	// condition
	if (prevprev == types.FilterKeywordDirection || prevprev == types.FilterKeywordDirectionSugared) &&
		firstTopLevelBinaryOpPos > 0 && firstTopLevelBinaryOp != "&" {
		return false
	}

	// an 'unnested' disjunction is disallowed if the dir keyword is already present
	if sugg.token == "|" && dirKeywordOccurrences > 0 && openParens == 0 {
		return false
	}

	// if dir keyword has already occurred and there is already a top-level conjunction,
	// no other top-level conjunction is allowed (otherwise dir keyword would not be
	// part of the top-level conjunct anymore)
	if sugg.token == "&" && dirKeywordOccurrences > 0 && topLevelAndOccurred && openParens == 0 {
		return false
	}

	return true
}

// conditionMustEnd checks whether the condition string must end now
// in order to be a valid condition.
func conditionMustEnd(tokens []string, prev, last string, suggs []suggestion, openParens, dirKeywordOccurrences int) bool {

	// If there are no suggestions, and the previous or current
	//condition is a direction filter, the query must end (no other
	// conditions are allowed afterwards).
	// Note: this case is only possible for a dir keyword occuring
	// on the right of a conjunction
	if len(suggs) == 0 {
		for _, direction := range types.DirectionFilters {
			if prev == string(direction) || last == string(direction) {
				return true
			}
		}
	}

	// If there are no suggestions, and the dir keyword
	// has already occurred, and the current position is
	// directly after a complete top level condition
	// (no open parentheses + prev is not a logical operator) the query must end.
	// Note: this case handles the occurrences of the
	// dir keyword on the left side of a conjunction
	if len(suggs) == 0 && dirKeywordOccurrences > 0 && openParens == 0 && last != "" {
		switch prev {
		case "=", "!=", "<", ">", "<=", ">=":
			return false
		default:
			return true
		}

	}
	// If there is exactly one suggestion, and the previous or current
	// condition is a direction filter and this suggestion is
	// exactly what the user specified
	if len(suggs) == 1 {
		for _, direction := range types.DirectionFilters {
			if suggs[0].token == string(direction) && suggs[0].token == last && len(tokens) > 3 {
				return true
			}
		}
	}
	return false
}
