#!/bin/sh

PROGRAM=${0##*/}
PROVIDER=/usr/lib/ssh-keychain.dylib
SSH_ADD=/usr/bin/ssh-add
SSH_KEYGEN=/usr/bin/ssh-keygen
TRUE=/usr/bin/true

SC_AUTH=
TEMP_DIR=
IDENTITIES_FILE=
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
  -e, --export-key HASH         Print an OpenSSH public key
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

ssh_hashes() {
	awk '
		$1 == "p-256-ne" &&
		length($2) == 40 && $2 ~ /^[0123456789abcdefABCDEF]+$/ &&
		!seen[toupper($2)]++ {
			if (hashes != "")
				hashes = hashes ";"
			hashes = hashes toupper($2)
		}
		END { print hashes }
	' "$IDENTITIES_FILE"
}

add_to_agent() {
	require_macos
	require_sc_auth
	require_provider
	[ -x "$SSH_ADD" ] || fail "required command not found: $SSH_ADD"
	[ -n "${SSH_AUTH_SOCK:-}" ] || fail 'SSH_AUTH_SOCK is not set'
	capture_identities || exit $?

	SSH_HASHES=$(ssh_hashes)
	[ -n "$SSH_HASHES" ] || fail 'no SSH-compatible p-256-ne identities found'

	KEYCHAIN_CERTIFICATES=$SSH_HASHES \
	SSH_ASKPASS_REQUIRE=force \
	SSH_ASKPASS=$TRUE \
		"$SSH_ADD" -K -S "$PROVIDER"
}

export_key() {
	validate_hash "$1"
	require_macos
	require_sc_auth
	require_provider
	[ -x "$SSH_KEYGEN" ] || fail "required command not found: $SSH_KEYGEN"
	capture_identities || exit $?

	if ! find_identity p-256-ne; then
		if find_identity non-exportable; then
			fail 'Apple SSH supports exporting only p-256-ne identities'
		fi
		fail "no non-exportable identity found for hash $HASH"
	fi

	EXPORT_DIR=$TEMP_DIR/export
	DOWNLOAD_OUTPUT=$TEMP_DIR/ssh-keygen.out
	mkdir "$EXPORT_DIR" || fail 'could not prepare temporary export storage'

	(
		cd "$EXPORT_DIR" || exit 1
		KEYCHAIN_CERTIFICATES=$HASH \
		SSH_ASKPASS_REQUIRE=force \
		SSH_ASKPASS=$TRUE \
			"$SSH_KEYGEN" -q -K -w "$PROVIDER" -N '' \
			</dev/null >"$DOWNLOAD_OUTPUT"
	)
	export_status=$?
	if [ "$export_status" -ne 0 ]; then
		[ ! -s "$DOWNLOAD_OUTPUT" ] || cat "$DOWNLOAD_OUTPUT" >&2
		error "could not export identity $HASH"
		return "$export_status"
	fi

	set -- "$EXPORT_DIR"/*.pub
	if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
		fail 'the SSH provider did not return exactly one public key'
	fi
	PUBLIC_KEY_FILE=$1
	KEY_HANDLE_FILE=${PUBLIC_KEY_FILE%.pub}
	[ -f "$KEY_HANDLE_FILE" ] || fail 'the SSH provider returned an incomplete key'

	if ! awk '
		NR == 1 && $1 == "sk-ecdsa-sha2-nistp256@openssh.com" && NF >= 2 {
			valid = 1
		}
		NR > 1 { valid = 0 }
		END { exit valid ? 0 : 1 }
	' "$PUBLIC_KEY_FILE"; then
		fail 'the SSH provider returned an invalid public key'
	fi

	cat "$PUBLIC_KEY_FILE"
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
