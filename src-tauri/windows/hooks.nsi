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

  ; Start the agent this install replaced, but only where nothing else will.
  ;
  ; Windows cannot overwrite a running .exe, so the template killed the old
  ; process before it wrote these files (CheckIfAppIsRunning). It starts one
  ; again in exactly two cases: a silent or passive install carrying /R, and an
  ; interactive install where the user leaves the finish-page checkbox ticked.
  ; A management tool installing silently without /R gets neither, and its
  ; machine runs no agent until the next logon.
  ;
  ; The condition covers that gap and nothing else. An interactive install is
  ; left to the finish page, which ticks its box by default; starting the agent
  ; here as well would launch it twice. The named mutex absorbs a double start
  ; only for a production build — lib.rs registers tauri_plugin_single_instance
  ; behind is_production_target — and two agents is PROD-4603, which this repo
  ; has shipped once already.
  ;
  ; RunAsUser starts the agent as the logged-in user, never as the elevated
  ; installer, so the credential store stays with the person at the machine. It
  ; pushes one result: zero for success, one for failure. Read it. It returns
  ; failure when the caller is elevated and there is no shell window, and an
  ; unread failure is the silent no-agent install this hook exists to prevent.
  ${If} ${Silent}
  ${OrIf} $PassiveMode = 1
    ClearErrors
    ${GetOptions} $CMDLINE "/R" $R9
    ${If} ${Errors}
      nsis_tauri_utils::RunAsUser "$INSTDIR\${MAINBINARYNAME}.exe" ""
      Pop $R9
      ${If} $R9 <> 0
        ; The one shape that sets this flag is the least able to show it: an
        ; elevated caller with no shell window, which is a management tool
        ; running as SYSTEM. Such an install has no console for AttachConsole
        ; and reads no install log, so the exit code is the only channel that
        ; reaches it. SetErrorLevel marks the install without aborting it — the
        ; files are in place and the Run key starts the agent at the next logon,
        ; so failing the whole install would be a lie and would send a
        ; management tool into a retry loop.
        ; 1000 is ours, not a Windows Installer code: 0 is success, and NSIS
        ; uses 1 for a user abort and 2 for a failed install. A tool that reads
        ; it learns the files landed and the agent did not start, which is
        ; neither of those.
        ;
        ; This does not contradict rejecting an abort above. An abort stops the
        ; install and leaves the machine without the new files; this finishes
        ; the install and marks it. Both are non-zero, so a deployment tool
        ; still needs the mapping — the README's "Installer exit code 1000"
        ; section tells the admin to add it, since nothing else can.
        SetErrorLevel 1000
        DetailPrint "KlaayGuard: the agent did not start; it starts at the next logon"
        Push $0
        System::Call 'kernel32::AttachConsole(i -1)i.r0'
        ${If} $0 <> 0
          System::Call 'kernel32::GetStdHandle(i -11)i.r0'
          FileWrite $0 "KlaayGuard: the agent did not start; it starts at the next logon$\n"
        ${EndIf}
        Pop $0
      ${EndIf}
    ${EndIf}
  ${EndIf}
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
