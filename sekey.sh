#!/bin/sh

PROGRAM=${0##*/}
PROVIDER=/usr/lib/ssh-keychain.dylib
SC_AUTH=/usr/sbin/sc_auth
SSH_ADD=/usr/bin/ssh-add
SSH_KEYGEN=/usr/bin/ssh-keygen
TRUE=/usr/bin/true

TEMP_DIR=
IDENTITIES_FILE=
SSH_IDENTITIES_FILE=
IDENTITY_MAP_FILE=
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
  -e, --export-key HASH         Print a public key already in ssh-agent
  -a, --add-to-agent            Add all SSH-compatible keys to ssh-agent

HASH is the 40-character CTK hash shown by --list-keys. Export is read-only
and fails if the key is not already in ssh-agent. Export and agent operations
support p-256-ne identities. Requires macOS 26 or newer. Do not run with sudo.
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
	if [ "$(/usr/bin/uname -s 2>/dev/null)" != Darwin ]; then
		fail 'this operation requires macOS'
	fi
}

require_supported_version() {
	macos_version=$(/usr/bin/sw_vers -productVersion 2>/dev/null) ||
		fail 'could not determine the macOS version'
	macos_major=${macos_version%%.*}
	case $macos_major in
		'' | *[!0123456789]*)
			fail "unsupported macOS version: $macos_version"
			;;
	esac
	[ "$macos_major" -ge 26 ] ||
		fail "macOS 26 or newer is required (found $macos_version)"
}

require_unprivileged_user() {
	user_id=$(/usr/bin/id -u 2>/dev/null) || fail 'could not determine user ID'
	if [ "$user_id" -eq 0 ] || [ -n "${SUDO_USER:-}" ] ||
		[ -n "${SUDO_UID:-}" ]; then
		fail 'do not run this script as root or with sudo'
	fi
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
	return $?
}

preflight() {
	require_macos
	require_supported_version
	require_unprivileged_user
	[ -x "$SC_AUTH" ] || fail "required Apple command not found: $SC_AUTH"
	capture_identities || exit $?
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

build_identity_map() {
	IDENTITY_MAP_FILE=$TEMP_DIR/identity-map
	: >"$IDENTITY_MAP_FILE"
	capture_ssh_identities || return $?

	awk '
		function signature(    value, field) {
			value = $1
			for (field = 3; field <= NF; field++)
				value = value SUBSEP $field
			return value
		}
		FILENAME == ARGV[1] {
			if (FNR > 1 && $1 == "p-256-ne") {
				value = signature()
				hash = toupper($2)
				default_count[value]++
				hash_count[hash]++
				default_hash[value] = hash
			}
			next
		}
		FNR > 1 && $1 == "p-256-ne" && $2 ~ /^SHA256:/ {
			value = signature()
			ssh_count[value]++
			fingerprint_count[$2]++
			ssh_fingerprint[value] = $2
		}
		END {
			for (value in default_hash) {
				hash = default_hash[value]
				fingerprint = ssh_fingerprint[value]
				if (default_count[value] == 1 && ssh_count[value] == 1 &&
				    hash_count[hash] == 1 && fingerprint_count[fingerprint] == 1)
					print hash, fingerprint
			}
		}
	' "$IDENTITIES_FILE" "$SSH_IDENTITIES_FILE" >"$IDENTITY_MAP_FILE"
}

find_ssh_fingerprint() {
	SSH_FINGERPRINT=$(awk -v hash="$HASH" '
		toupper($1) == hash { print $2 }
	' "$IDENTITY_MAP_FILE")
	case $SSH_FINGERPRINT in
		SHA256:?*) return 0 ;;
		*) return 1 ;;
	esac
}

print_non_exportable_keys() {
	awk '
		FILENAME == ARGV[1] {
			fingerprint[toupper($1)] = $2
			next
		}
		FNR == 1 { header = $0; next }
		$1 ~ /-ne$/ {
			if (!found)
				print header
			print
			if ($1 != "p-256-ne")
				value = "unavailable (not SSH-compatible)"
			else if (fingerprint[toupper($2)] != "")
				value = fingerprint[toupper($2)]
			else
				value = "unavailable"
			print "  SSH fingerprint: " value
			found = 1
		}
		END {
			if (!found)
				print "No non-exportable CTK identities found."
		}
	' "$IDENTITY_MAP_FILE" "$IDENTITIES_FILE"
}

print_ssh_compatible_keys() {
	awk '
		FILENAME == ARGV[1] {
			fingerprint[toupper($1)] = $2
			next
		}
		FNR == 1 { header = $0; next }
		$1 == "p-256-ne" {
			if (!found)
				print header
			print
			if (fingerprint[toupper($2)] != "")
				value = fingerprint[toupper($2)]
			else
				value = "unavailable"
			print "  SSH fingerprint: " value
			found = 1
		}
		END {
			if (!found)
				print "No SSH-compatible non-exportable CTK identities found."
		}
	' "$IDENTITY_MAP_FILE" "$IDENTITIES_FILE"
}

list_keys() {
	preflight
	build_identity_map || :
	print_non_exportable_keys
}

generate_keypair() {
	LABEL=$1
	case $LABEL in
		'') usage_error 'LABEL must not be empty' ;;
		-*) usage_error 'LABEL must not begin with a hyphen' ;;
	esac

	preflight
	"$SC_AUTH" create-ctk-identity -l "$LABEL" -k p-256-ne -t bio
}

delete_keypair() {
	validate_hash "$1"
	preflight

	if ! find_identity non-exportable; then
		fail "no non-exportable identity found for hash $HASH"
	fi

	build_identity_map || :
	printf 'Identity to delete permanently:\n' >&2
	cat "$MATCH_FILE" >&2
	match_type=$(awk 'NR == 1 { print $1 }' "$MATCH_FILE")
	if [ "$match_type" = p-256-ne ] && find_ssh_fingerprint; then
		printf 'SSH fingerprint: %s\n' "$SSH_FINGERPRINT" >&2
	elif [ "$match_type" = p-256-ne ]; then
		printf 'SSH fingerprint: unavailable\n' >&2
	else
		printf 'SSH fingerprint: unavailable (not SSH-compatible)\n' >&2
	fi
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
				awk 'NR == 1 { print $1, $2, "ssh:" }' \
					"$CANDIDATE_FILE" >>"$AGENT_MATCH_FILE"
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
	preflight
	load_agent_keys quiet || return $?
	build_identity_map || :
	printf 'SSH-compatible CTK identities available to ssh-agent:\n'
	print_ssh_compatible_keys
}

export_key() {
	validate_hash "$1"
	preflight

	if ! find_identity p-256-ne; then
		if find_identity non-exportable; then
			fail 'Apple SSH supports exporting only p-256-ne identities'
		fi
		fail "no non-exportable identity found for hash $HASH"
	fi

	if ! build_identity_map || ! find_ssh_fingerprint; then
		fail "could not map identity $HASH to an SSH fingerprint"
	fi

	capture_agent_keys || return $?
	find_agent_public_key
	match_status=$?
	if [ "$match_status" -eq 2 ]; then
		fail "ssh-agent contains multiple entries for $SSH_FINGERPRINT"
	fi
	if [ "$match_status" -eq 1 ]; then
		fail "identity $HASH is not loaded in ssh-agent; run '$PROGRAM --add-to-agent' first (it adds all compatible identities)"
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
