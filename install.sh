#!/bin/sh
set -eu

TIKTI_REPO_URL="${TIKTI_REPO_URL:-https://github.com/osvaldoandrade/tikti.git}"
TIKTI_REF="${TIKTI_REF:-main}" # branch, tag, or commit sha
TIKTI_BIN_NAME="${TIKTI_BIN_NAME:-tikti-cli}"
TIKTI_PKG="${TIKTI_PKG:-./cmd/tikti-cli}"
TIKTI_BIN_DIR="${TIKTI_BIN_DIR:-}"

say() { printf '%s\n' "$*"; }
warn() { printf '%s\n' "warning: $*" >&2; }
die() { printf '%s\n' "error: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing dependency: $1"; }

uname_s="$(uname -s 2>/dev/null || printf unknown)"
os="unknown"
case "$uname_s" in
	Darwin*) os="darwin" ;;
	Linux*) os="linux" ;;
	MINGW* | MSYS* | CYGWIN*) os="windows" ;;
esac

exe=""
if [ "$os" = "windows" ]; then
	exe=".exe"
fi

find_writable_path_dir() {
	old_ifs="$IFS"
	IFS=":"
	for p in $PATH; do
		[ -n "${p:-}" ] || continue
		[ "$p" = "." ] && continue
		if [ -d "$p" ] && [ -w "$p" ]; then
			IFS="$old_ifs"
			printf '%s' "$p"
			return 0
		fi
	done
	IFS="$old_ifs"
	return 1
}

bin_dir="$TIKTI_BIN_DIR"
if [ -z "$bin_dir" ]; then
	if bin_dir="$(find_writable_path_dir 2>/dev/null)"; then
		:
	else
		if [ "$os" = "windows" ]; then
			bin_dir="${HOME}/bin"
		else
			bin_dir="${HOME}/.local/bin"
		fi
	fi
fi

mkdir -p "$bin_dir"

need go
need git

tmp_dir="$(mktemp -d 2>/dev/null || mktemp -d -t tikti-install)"
cleanup() { rm -rf "$tmp_dir"; }
trap cleanup EXIT INT TERM

src_dir="$tmp_dir/src"
mkdir -p "$src_dir"

say "Installing ${TIKTI_BIN_NAME}${exe} (${TIKTI_REF}) from ${TIKTI_REPO_URL}"

git init -q "$src_dir"
git -C "$src_dir" remote add origin "$TIKTI_REPO_URL"
git -C "$src_dir" fetch -q --depth 1 origin "$TIKTI_REF"
git -C "$src_dir" checkout -q FETCH_HEAD

out_path="$tmp_dir/${TIKTI_BIN_NAME}${exe}"
(
	cd "$src_dir"
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$out_path" "$TIKTI_PKG"
)

dest_path="${bin_dir%/}/${TIKTI_BIN_NAME}${exe}"
if command -v install >/dev/null 2>&1; then
	install -m 0755 "$out_path" "$dest_path"
else
	cp "$out_path" "$dest_path"
	chmod 0755 "$dest_path" 2>/dev/null || true
fi

say "Installed to: $dest_path"
case ":$PATH:" in
	*":$bin_dir:"*) ;;
	*)
		warn "install dir is not on PATH: $bin_dir"
		if [ "$os" = "windows" ]; then
			warn "add it to PATH (Git Bash): export PATH=\"$bin_dir:\$PATH\" (persist in ~/.bashrc)"
		else
			warn "add it to PATH (bash/zsh): export PATH=\"$bin_dir:\$PATH\" (persist in ~/.profile or ~/.zshrc)"
		fi
		;;
esac
