#!/bin/sh

PROGRAM=${0##*/}
PROVIDER=/usr/lib/ssh-keychain.dylib
SSH_ADD=/usr/bin/ssh-add
SSH_KEYGEN=/usr/bin/ssh-keygen
TRUE=/usr/bin/true

SC_AUTH=
TEMP_DIR=
IDENTITIES_FILE=
SSH_IDENTITIES_FILE=
MATCH_FILE=

usage() {
	cat <<EOF
Usage: $PROGRAM OPTION

Manage non-exportable SSH keypairs in Apple Secure Enclave.

Options:
  -h, --help                    Show this help
  -l, --list-keys               List non-exportable CTK identities
  -c, --generate-keypair LABEL  Generate a Touch ID-protected keypair
  -d, --delete-keypair HASH     Delete a keypair after confirmation
  -e, --export-key HASH         Print an OpenSSH public key via ssh-agent
  -a, --add-to-agent            Add all SSH-compatible keys to ssh-agent

HASH is the 40-character hash shown by --list-keys. Export and agent
operations support p-256-ne identities. Requires macOS 26 or newer.
EOF
}

error() {
	printf '%s: %s\n' "$PROGRAM" "$*" >&2
}

fail() {
	error "$*"
	exit 1
}

usage_error() {
	error "$*"
	printf "Try '%s --help' for more information.\n" "$PROGRAM" >&2
	exit 2
}

cleanup() {
	cleanup_dir=$TEMP_DIR
	TEMP_DIR=
	if [ -n "$cleanup_dir" ]; then
		rm -rf "$cleanup_dir"
	fi
}

trap cleanup 0
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

require_macos() {
	if [ "$(uname -s 2>/dev/null)" != Darwin ]; then
		fail 'this operation requires macOS'
	fi
}

require_sc_auth() {
	if [ -x /usr/sbin/sc_auth ]; then
		SC_AUTH=/usr/sbin/sc_auth
	else
		SC_AUTH=$(command -v sc_auth 2>/dev/null) ||
			fail 'sc_auth was not found'
	fi
}

require_provider() {
	[ -r "$PROVIDER" ] || fail "SSH provider not found: $PROVIDER"
	[ -x "$TRUE" ] || fail "required command not found: $TRUE"
}

make_temp_dir() {
	[ -n "$TEMP_DIR" ] && return 0
	TEMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/sekey.XXXXXXXX") ||
		fail 'could not create a temporary directory'
}

capture_identities() {
	make_temp_dir
	IDENTITIES_FILE=$TEMP_DIR/identities
	"$SC_AUTH" list-ctk-identities >"$IDENTITIES_FILE"
	capture_status=$?
	if [ "$capture_status" -ne 0 ]; then
		error 'could not list CTK identities'
		return "$capture_status"
	fi
}

capture_ssh_identities() {
	make_temp_dir
	SSH_IDENTITIES_FILE=$TEMP_DIR/ssh-identities
	"$SC_AUTH" list-ctk-identities -t ssh >"$SSH_IDENTITIES_FILE"
	capture_status=$?
	if [ "$capture_status" -ne 0 ]; then
		error 'could not list SSH fingerprints for CTK identities'
		return "$capture_status"
	fi
}

validate_hash() {
	HASH=$1
	case $HASH in
		'' | *[!0123456789abcdefABCDEF]*)
			usage_error 'HASH must contain exactly 40 hexadecimal characters'
			;;
	esac
	[ "${#HASH}" -eq 40 ] ||
		usage_error 'HASH must contain exactly 40 hexadecimal characters'
	HASH=$(printf '%s' "$HASH" | tr '[:lower:]' '[:upper:]')
}

find_identity() {
	find_type=$1
	MATCH_FILE=$TEMP_DIR/match
	awk -v hash="$HASH" -v type="$find_type" '
		toupper($2) == hash &&
		((type == "non-exportable" && $1 ~ /-ne$/) || $1 == type) {
			print
			matches++
		}
		END { exit matches == 1 ? 0 : 1 }
	' "$IDENTITIES_FILE" >"$MATCH_FILE"
}

find_ssh_fingerprint() {
	capture_ssh_identities || return $?

	if ! SSH_FINGERPRINT=$(awk -v hash="$HASH" '
		function signature(    value, field) {
			value = $1
			for (field = 3; field <= NF; field++)
				value = value SUBSEP $field
			return value
		}
		FNR == NR {
			if (FNR > 1 && $1 == "p-256-ne" && toupper($2) == hash) {
				selected_signature = signature()
				selected++
			}
			next
		}
		FNR > 1 && signature() == selected_signature {
			print $2
			matches++
		}
		END { exit selected == 1 && matches == 1 ? 0 : 1 }
	' "$IDENTITIES_FILE" "$SSH_IDENTITIES_FILE"); then
		return 1
	fi

	case $SSH_FINGERPRINT in
		SHA256:?*) return 0 ;;
		*) return 1 ;;
	esac
}

list_keys() {
	require_macos
	require_sc_auth
	capture_identities || exit $?

	awk '
		NR == 1 { header = $0; next }
		$1 ~ /-ne$/ {
			if (!found)
				print header
			print
			found = 1
		}
		END {
			if (!found)
				print "No non-exportable CTK identities found."
		}
	' "$IDENTITIES_FILE"
}

generate_keypair() {
	LABEL=$1
	case $LABEL in
		'') usage_error 'LABEL must not be empty' ;;
		-*) usage_error 'LABEL must not begin with a hyphen' ;;
	esac

	require_macos
	require_sc_auth
	"$SC_AUTH" create-ctk-identity -l "$LABEL" -k p-256-ne -t bio
}

delete_keypair() {
	validate_hash "$1"
	require_macos
	require_sc_auth
	capture_identities || exit $?

	if ! find_identity non-exportable; then
		fail "no non-exportable identity found for hash $HASH"
	fi

	printf 'Identity to delete permanently:\n' >&2
	cat "$MATCH_FILE" >&2
	if ! printf "Type 'delete' to continue: " >/dev/tty 2>/dev/null; then
		fail 'deletion requires an interactive terminal'
	fi
	if ! IFS= read -r confirmation </dev/tty; then
		fail 'could not read confirmation from the terminal'
	fi
	if [ "$confirmation" != delete ]; then
		printf 'Deletion cancelled.\n' >&2
		return 0
	fi

	"$SC_AUTH" delete-ctk-identity -h "$HASH"
	delete_status=$?
	if [ "$delete_status" -eq 0 ]; then
		printf 'Deleted identity %s.\n' "$HASH" >&2
		printf 'If it was loaded in ssh-agent, its stale entry may remain until the agent is refreshed.\n' >&2
		return 0
	fi

	error "could not delete identity $HASH"
	return "$delete_status"
}

require_agent() {
	require_provider
	[ -x "$SSH_ADD" ] || fail "required command not found: $SSH_ADD"
	[ -x "$SSH_KEYGEN" ] || fail "required command not found: $SSH_KEYGEN"
	[ -n "${SSH_AUTH_SOCK:-}" ] || fail 'SSH_AUTH_SOCK is not set'
}

load_agent_keys() {
	if [ "${1:-}" = quiet ]; then
		SSH_ASKPASS_REQUIRE=force \
		SSH_ASKPASS=$TRUE \
			"$SSH_ADD" -q -K -S "$PROVIDER"
		return $?
	fi

	SSH_ASKPASS_REQUIRE=force \
	SSH_ASKPASS=$TRUE \
		"$SSH_ADD" -K -S "$PROVIDER"
}

capture_agent_keys() {
	AGENT_KEYS_FILE=$TEMP_DIR/agent-keys
	AGENT_ERROR_FILE=$TEMP_DIR/agent-error
	"$SSH_ADD" -L >"$AGENT_KEYS_FILE" 2>"$AGENT_ERROR_FILE"
	agent_status=$?
	case $agent_status in
		0) return 0 ;;
		1)
			: >"$AGENT_KEYS_FILE"
			return 0
			;;
		*)
			cat "$AGENT_ERROR_FILE" >&2
			return "$agent_status"
			;;
	esac
}

find_agent_public_key() {
	AGENT_MATCH_FILE=$TEMP_DIR/agent-match
	CANDIDATE_FILE=$TEMP_DIR/candidate.pub
	FINGERPRINT_FILE=$TEMP_DIR/candidate.fingerprint
	: >"$AGENT_MATCH_FILE"

	while IFS= read -r public_key; do
		[ -n "$public_key" ] || continue
		printf '%s\n' "$public_key" >"$CANDIDATE_FILE"
		if "$SSH_KEYGEN" -E sha256 -lf "$CANDIDATE_FILE" \
			>"$FINGERPRINT_FILE" 2>/dev/null; then
			candidate_fingerprint=$(awk 'NR == 1 { print $2 }' \
				"$FINGERPRINT_FILE")
			if [ "$candidate_fingerprint" = "$SSH_FINGERPRINT" ]; then
				printf '%s\n' "$public_key" >>"$AGENT_MATCH_FILE"
			fi
		fi
	done <"$AGENT_KEYS_FILE"

	agent_matches=$(awk 'END { print NR + 0 }' "$AGENT_MATCH_FILE")
	case $agent_matches in
		1) return 0 ;;
		0) return 1 ;;
		*) return 2 ;;
	esac
}

add_to_agent() {
	require_macos
	require_agent
	load_agent_keys
}

export_key() {
	validate_hash "$1"
	require_macos
	require_sc_auth
	require_agent
	capture_identities || exit $?

	if ! find_identity p-256-ne; then
		if find_identity non-exportable; then
			fail 'Apple SSH supports exporting only p-256-ne identities'
		fi
		fail "no non-exportable identity found for hash $HASH"
	fi

	if ! find_ssh_fingerprint; then
		fail "could not map identity $HASH to an SSH fingerprint"
	fi

	capture_agent_keys || return $?
	find_agent_public_key
	match_status=$?
	if [ "$match_status" -eq 2 ]; then
		fail "ssh-agent contains multiple entries for $SSH_FINGERPRINT"
	fi
	if [ "$match_status" -eq 1 ]; then
		load_agent_keys quiet || return $?
		capture_agent_keys || return $?
		find_agent_public_key
		match_status=$?
		case $match_status in
			0) ;;
			1) fail "SSH provider did not add identity $HASH to ssh-agent" ;;
			2) fail "ssh-agent contains multiple entries for $SSH_FINGERPRINT" ;;
		esac
	fi

	cat "$AGENT_MATCH_FILE"
}

if [ "$#" -eq 0 ]; then
	usage
	exit 0
fi

OPTION=$1
shift

case $OPTION in
	-h | --help)
		[ "$#" -eq 0 ] || usage_error 'help does not accept arguments'
		usage
		;;
	-l | --list-keys)
		[ "$#" -eq 0 ] || usage_error 'list-keys does not accept arguments'
		list_keys
		;;
	-c | --generate-keypair)
		[ "$#" -eq 1 ] || usage_error 'generate-keypair requires exactly one LABEL'
		generate_keypair "$1"
		;;
	-d | --delete-keypair)
		[ "$#" -eq 1 ] || usage_error 'delete-keypair requires exactly one HASH'
		delete_keypair "$1"
		;;
	-e | --export-key)
		[ "$#" -eq 1 ] || usage_error 'export-key requires exactly one HASH'
		export_key "$1"
		;;
	-a | --add-to-agent)
		[ "$#" -eq 0 ] || usage_error 'add-to-agent does not accept arguments'
		add_to_agent
		;;
	*)
		usage_error "unknown option: $OPTION"
		;;
esac
