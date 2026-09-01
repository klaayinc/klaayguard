#!/bin/sh
# Refresh the desktop databases after removal so the menu entry stops being
# advertised once the package is gone.
set -e
update-desktop-database -q /usr/share/applications || true
gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true
