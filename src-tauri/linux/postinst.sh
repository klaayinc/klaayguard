#!/bin/sh
# Refresh the desktop databases so the app icon and menu entry are known at
# once, without a logout. Distros without file triggers need this.
set -e
update-desktop-database -q /usr/share/applications || true
gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true
