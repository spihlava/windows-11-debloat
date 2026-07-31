#!/usr/bin/env bash
# Item 4 of the approved change set: move package caches off the ext4.vhdx onto the
# bare-metal /dev/sde1 passthrough. Run AFTER the reboot, BEFORE the --set-sparse step
# (freeing the blocks first is what gives sparse something to reclaim).
#
#   bash /mnt/wsl/PHYSICALDRIVE3p1/windows-11-debloat/post-reboot-wsl-tune.sh
set -euo pipefail

DEST=/mnt/wsl/PHYSICALDRIVE3p1/caches

mountpoint -q /mnt/wsl/PHYSICALDRIVE3p1 || {
  echo "ERROR: /mnt/wsl/PHYSICALDRIVE3p1 not mounted. Check the 'WSL Mount Projects Disk' task ran." >&2
  exit 1
}

if pgrep -f 'npm exec|uv run|node ' | grep -qv "^$$\$"; then
  echo "Running toolchain processes found - stop them first:" >&2
  pgrep -a -f 'npm exec|uv run|node ' >&2
  exit 1
fi

mkdir -p "$DEST"
# cp -a preserves hardlinks within each tree (uv's cache relies on them heavily);
# a plain cross-filesystem mv would explode 6.4 GB into many times that.
for pair in "$HOME/.cache/uv:uv" "$HOME/.npm:npm" "$HOME/.cache/pip:pip"; do
  src=${pair%:*}; name=${pair#*:}
  [ -d "$src" ] || { echo "skip $name (no $src)"; continue; }
  echo "moving $src -> $DEST/$name"
  cp -a "$src" "$DEST/$name"
  rm -rf "$src"
  ln -s "$DEST/$name" "$src"   # symlink back so anything with a hardcoded path still works
done

# Env vars for tools that ignore the default location.
marker='# --- dev-latency tuning: caches on bare-metal ext4 ---'
if ! grep -qF "$marker" "$HOME/.bashrc"; then
  cat >> "$HOME/.bashrc" <<EOF

$marker
# ponytail: no mount guard here - if the passthrough disk fails to mount, these paths
# land back on the VHDX via /mnt/wsl. Add a mountpoint check in .bashrc if that bites.
export UV_CACHE_DIR=$DEST/uv
export npm_config_cache=$DEST/npm
export PIP_CACHE_DIR=$DEST/pip
EOF
  echo "appended cache env vars to ~/.bashrc"
fi

echo
echo "done. verify:"
echo "  du -sh $DEST/*"
echo "  df -h / /mnt/wsl/PHYSICALDRIVE3p1"
echo "then run the --set-sparse step from Windows (see summary)."
