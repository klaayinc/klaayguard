; Tauri inserts only four hook macros: NSIS_HOOK_PREINSTALL, NSIS_HOOK_POSTINSTALL,
; NSIS_HOOK_PREUNINSTALL, and NSIS_HOOK_POSTUNINSTALL. The earlier customInstall
; and customRemove macros in this file were never invoked, so nothing they wrote
; ever reached the registry.
;
; The klaayguard:// protocol needs no hook. The Tauri template registers every
; scheme from the deep-link plugin config under $SHCTX\Software\Classes, and
; removes them again at uninstall.
;
; NSIS does not escape with a backslash. Write registry paths with single
; backslashes; a doubled one is a literal doubled backslash in the key name.

!macro NSIS_HOOK_POSTINSTALL
  ; Start KlaayGuard at user logon. HKCU needs no admin rights and runs the
  ; agent as the logged-in user, so posture reports stay continuous. This
  ; mirrors the macOS LaunchAgent and the Linux XDG autostart entry. A silent
  ; self-update reruns this installer, so every update refreshes the value.
  ; The template's uninstaller deletes this value itself (it is the name
  ; tauri-plugin-autostart uses), so no POSTUNINSTALL hook is needed for it.
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "KlaayGuard" '"$INSTDIR\${MAINBINARYNAME}.exe"'

  ; Start the agent this install replaced. Windows cannot overwrite a running
  ; .exe, so the template killed the old process before it wrote these files
  ; (CheckIfAppIsRunning). It starts one again only for a silent or passive
  ; install carrying /R, or when the user leaves the finish-page checkbox
  ; ticked. A person who unticks that box, and a management tool installing
  ; silently without /R, are both left with no agent until the next logon.
  ;
  ; Stand aside when /R is present: the template's .onInstSuccess starts it,
  ; and that is the path the self-updater takes. RunAsUser starts the agent as
  ; the logged-in user, never as the elevated installer, so the credential
  ; store and the single-instance mutex stay with the person using the machine.
  Push $R9
  ClearErrors
  ${GetOptions} $CMDLINE "/R" $R9
  ${If} ${Errors}
    nsis_tauri_utils::RunAsUser "$INSTDIR\${MAINBINARYNAME}.exe" ""
  ${EndIf}
  Pop $R9
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ; A real uninstall, not the in-place reinstall the installer runs with
  ; /UPDATE, must leave no credential behind: the bearer token lives in
  ; Credential Manager or a fallback file, and nothing else clears either.
  ; The template has already stopped the running agent at this point, and
  ; the seam exits before Tauri starts, so it never contends with it.
  ${If} $UpdateMode <> 1
    ExecWait '"$INSTDIR\${MAINBINARYNAME}.exe" --forget-credentials'
  ${EndIf}
!macroend
