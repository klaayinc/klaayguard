; Tauri's NSIS template already includes FileAssociation.nsh; re-including it
; double-defines its macros (e.g. APP_ASSOCIATE) and aborts makensis. These hooks
; only need raw registry writes, so no extra include is required.

!macro customInstall
  ; Register klaayguard custom protocol to launch the app with the URL as argument
  WriteRegStr HKCR "klaayguard" "" "URL:KlaayGuard Protocol"
  WriteRegStr HKCR "klaayguard" "URL Protocol" ""
  WriteRegStr HKCR "klaayguard\\DefaultIcon" "" "$INSTDIR\\klaayguard.exe,1"
  WriteRegStr HKCR "klaayguard\\shell\\open\\command" "" '"$INSTDIR\\klaayguard.exe" "%1"'
!macroend

!macro customRemove
  DeleteRegKey HKCR "klaayguard"
!macroend


