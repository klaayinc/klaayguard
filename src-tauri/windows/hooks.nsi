!include "FileAssociation.nsh"

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


