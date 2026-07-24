#!/bin/sh

PROGRAM=${0##*/}
PROVIDER=/usr/lib/ssh-keychain.dylib
SC_AUTH=/usr/sbin/sc_auth
SSH_ADD=/usr/bin/ssh-add
SSH_KEYGEN=/usr/bin/ssh-keygen
TRUE=/usr/bin/true

TEMP_DIR=

usage() {
	cat <<EOF
Usage: $PROGRAM OPTION

Manage non-exportable SSH keypairs in Apple Secure Enclave.

Options:
  -h, --help                    Show this help
  -l, --list-keys               List SSH keypairs in Apple Secure Enclave
  -c, --generate-keypair LABEL  Generate a Touch ID-protected keypair
  -d, --delete-keypair HASH     Delete a keypair after confirmation
  -e, --export-key HASH         Print a public key already in ssh-agent
  -a, --add-to-agent            Add all SSH-compatible keypairs to ssh-agent

HASH is the 40-character public key hash shown by --list-keys. Export is read-only
and fails if the key is not already in ssh-agent. Export and agent operations
support p-256-ne keypairs. Requires macOS 26 or newer. Do not run with sudo.
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

preflight() {
	if [ "$(/usr/bin/uname -s 2>/dev/null)" != Darwin ]; then
		fail 'this operation requires macOS'
	fi

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

	user_id=$(/usr/bin/id -u 2>/dev/null) || fail 'could not determine user ID'
	if [ "$user_id" -eq 0 ] || [ -n "${SUDO_USER:-}" ] ||
		[ -n "${SUDO_UID:-}" ]; then
		fail 'do not run this script as root or with sudo'
	fi

	[ -x "$SC_AUTH" ] || fail "required Apple command not found: $SC_AUTH"
}

capture_identities() {
	if [ -z "$TEMP_DIR" ]; then
		TEMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/sekey.XXXXXXXX") ||
			fail 'could not create a temporary directory'
	fi

	"$SC_AUTH" list-ctk-identities >"$TEMP_DIR/identities"
	capture_status=$?
	if [ "$capture_status" -ne 0 ]; then
		error 'could not list SSH keypairs'
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
	awk -v hash="$HASH" -v type="$find_type" '
		toupper($2) == hash &&
		((type == "non-exportable" && $1 ~ /-ne$/) || $1 == type) {
			print
			matches++
		}
		END { exit matches == 1 ? 0 : 1 }
	' "$TEMP_DIR/identities" >"$TEMP_DIR/match"
}

build_identity_map() {
	: >"$TEMP_DIR/identity-map"
	"$SC_AUTH" list-ctk-identities -t ssh >"$TEMP_DIR/ssh-identities" ||
		return $?

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
	' "$TEMP_DIR/identities" "$TEMP_DIR/ssh-identities" \
		>"$TEMP_DIR/identity-map"
}

find_ssh_fingerprint() {
	SSH_FINGERPRINT=$(awk -v hash="$HASH" '
		toupper($1) == hash { print $2 }
	' "$TEMP_DIR/identity-map")
	case $SSH_FINGERPRINT in
		SHA256:?*) return 0 ;;
		*) return 1 ;;
	esac
}

print_keys() {
	awk -v ssh_only="$1" '
		FILENAME == ARGV[1] {
			fingerprint[toupper($1)] = $2
			next
		}
		FNR == 1 { next }
		$1 ~ /-ne$/ && (!ssh_only || $1 == "p-256-ne") {
			if (found)
				print ""
			print "Hash: " toupper($2)
			print "Label: " $4
			if ($1 != "p-256-ne")
				value = "unavailable (not SSH-compatible)"
			else if (fingerprint[toupper($2)] != "")
				value = fingerprint[toupper($2)]
			else
				value = "unavailable"
			print "Fingerprint: " value
			found = 1
		}
		END {
			if (!found) {
				if (ssh_only)
					print "No SSH-compatible keypairs found."
				else
					print "No SSH keypairs found."
			}
		}
	' "$TEMP_DIR/identity-map" "$TEMP_DIR/identities"
}

list_keys() {
	preflight
	capture_identities || exit $?
	build_identity_map || :
	print_keys 0
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
	capture_identities || exit $?

	if ! find_identity non-exportable; then
		fail "no non-exportable identity found for hash $HASH"
	fi

	build_identity_map || :
	printf 'Identity to delete permanently:\n' >&2
	cat "$TEMP_DIR/match" >&2
	match_type=$(awk 'NR == 1 { print $1 }' "$TEMP_DIR/match")
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
	SSH_ASKPASS_REQUIRE=force \
	SSH_ASKPASS=$TRUE \
		"$SSH_ADD" -q -K -S "$PROVIDER"
}

capture_agent_keys() {
	"$SSH_ADD" -L >"$TEMP_DIR/agent-keys" 2>"$TEMP_DIR/agent-error"
	agent_status=$?
	case $agent_status in
		0) return 0 ;;
		1)
			: >"$TEMP_DIR/agent-keys"
			return 0
			;;
		*)
			cat "$TEMP_DIR/agent-error" >&2
			return "$agent_status"
			;;
	esac
}

find_agent_public_key() {
	"$SSH_KEYGEN" -E sha256 -lf "$TEMP_DIR/agent-keys" \
		>"$TEMP_DIR/agent-fingerprints" 2>/dev/null || :

	awk -v fingerprint="$SSH_FINGERPRINT" '
		FILENAME == ARGV[1] {
			if ($2 == fingerprint)
				matching_line[FNR] = 1
			next
		}
		matching_line[FNR] {
			print $1, $2, "ssh:"
			matches++
		}
		END { exit matches == 1 ? 0 : matches == 0 ? 1 : 2 }
	' "$TEMP_DIR/agent-fingerprints" "$TEMP_DIR/agent-keys" \
		>"$TEMP_DIR/agent-match"
}

add_to_agent() {
	preflight
	capture_identities || exit $?
	load_agent_keys || return $?
	build_identity_map || :
	printf 'SSH-compatible keypairs available to ssh-agent:\n'
	print_keys 1
}

export_key() {
	validate_hash "$1"
	preflight
	capture_identities || exit $?

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

	cat "$TEMP_DIR/agent-match"
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
