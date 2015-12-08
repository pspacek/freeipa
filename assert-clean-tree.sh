#!/bin/bash
is_tree_clean() {
	test "$(git status --porcelain "$@")" == ""
	return $?
}

fatal() {
	echo "ERROR: ${1}, exiting ..."
	exit 2
}

is_tree_clean || fatal "Git tree must be clean before you start review"
