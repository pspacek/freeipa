#!/bin/bash
log_error() {
	echo "ERROR: ${1}, continuing ..."
	errs=(${errs[@]} "- ${1}\n")
}

set -o errexit -o nounset #-o xtrace

source assert-clean-tree.sh

LOGFILE="$(mktemp --suff=.log)"
exec > >(tee -i ${LOGFILE})
exec 2>&1

# gather all errors in one array and print error summary at the end
declare -a errs
errs=("Summary of detected errors:\n")

is_tree_clean || fatal "Git tree must be clean before you start review"

echo -n "make lint is running ... "
make --silent lint || log_error "make lint failed"

# Go backwards in history until you find a remote branch from which current
# branch was created. This will be used as base for git diff.
PATCHCNT=0
BASEBRANCH=""
CURRBRANCH="$(git branch --remote --contains)"
while [ "${BASEBRANCH}" == "" ]
do
	# grep -v omits name of the branch we started on
	BASEBRANCH="$(git branch --remote --contains "HEAD~${PATCHCNT}" | grep -v "^. ${CURRBRANCH}$" | head -n 1)"
	# output can show tracking branches like 'origin/HEAD -> origin/master', pick just one of them
	BASEBRANCH="$(echo "${BASEBRANCH}" | sed 's#^. \([^ ]\+\).*$#\1#')"
	PATCHCNT="$(expr "${PATCHCNT}" + 1)"
	if [ "${PATCHCNT}" -gt "100" ]
	then
		echo "git branch --remote --contains HEAD~${PATCHCNT} does not show remote branch suitable as diff base"
		fatal "That seems way to far in the past; stopping this futile iteration"
	fi
done
echo "Detected base branch: ${BASEBRANCH}"
echo -n "Checks will be made against following base commit: "
git log -1 --oneline ${BASEBRANCH}


./makeapi
is_tree_clean "API.txt" || log_error "./makeapi changed something"

./makeaci
is_tree_clean "ACI.txt" || log_error "./makeaci changed something"

git diff ${BASEBRANCH} -U0 | pep8 --diff || log_error "PEP8 --diff failed"

# if API.txt is changed require change in VERSION
if ! git diff ${BASEBRANCH} --quiet -- API.txt;
then
	git diff ${BASEBRANCH} --quiet -- VERSION && log_error "API.txt was changed without a change in VERSION"
fi

# print error summary
if [ "${#errs[*]}" != "1" ]
then
	echo -e "${errs[*]}"
	echo "Please see ${LOGFILE}"
	exit 1
else
	rm "${LOGFILE}"
	echo "No problems detected using lint, pep8, ./make{api,aci}, and VERSION"
fi
