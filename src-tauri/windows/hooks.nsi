; Tauri inserts only four hook macros: NSIS_HOOK_PREINSTALL, NSIS_HOOK_POSTINSTALL,
; NSIS_HOOK_PREUNINSTALL, and NSIS_HOOK_POSTUNINSTALL. The earlier customInstall
; and customRemove macros in this file were never invoked, so nothing they wrote
; ever reached the registry.
;
; The klaayguard:// protocol went with the loopback sign-in, and no plugin
; registers a scheme any more, so no hook adds or removes one.
;
; NSIS does not escape with a backslash. Write registry paths with single
; backslashes; a doubled one is a literal doubled backslash in the key name.
;
; This file is included before the template declares its variables and adds
; its plugin directory. Code that reads $PassiveMode or calls
; nsis_tauri_utils must therefore sit in a macro that a section expands, never
; in a Function here.

; Remove every earlier KlaayGuard install found under one Uninstall key root.
; ROOT is HKCU or HKLM. The caller sets the registry view.
;
; A match is an entry whose publisher is Klaay and whose name is KlaayGuard or
; the pre-rename klaay. NSIS compares strings without case, so the "klaay"
; publisher of the builds before `bundle.publisher` existed matches too.
;
; $R5 is the index into the key list. A removal shifts the keys that follow, so
; after one the scan starts again at zero. An entry that stays is counted in $3
; and passed over, so the scan always ends.
!macro KLAAYGUARD_REMOVE_EARLIER_UNDER ROOT
  StrCpy $R5 0
  ${Do}
    EnumRegKey $R6 ${ROOT} "Software\Microsoft\Windows\CurrentVersion\Uninstall" $R5
    ${If} $R6 == ""
      ${ExitDo}
    ${EndIf}
    StrCpy $R7 "Software\Microsoft\Windows\CurrentVersion\Uninstall\$R6"
    ReadRegStr $R8 ${ROOT} $R7 "DisplayName"
    ReadRegStr $R9 ${ROOT} $R7 "Publisher"
    StrCpy $R4 0
    ${If} $R9 == "Klaay"
      ${If} $R8 == "KlaayGuard"
      ${OrIf} $R8 == "klaay"
        StrCpy $R4 1
      ${EndIf}
    ${EndIf}

    ${If} $R4 = 1
      ReadRegDWORD $R9 ${ROOT} $R7 "WindowsInstaller"
      ${If} $R9 = 1
        ; An .msi install, which early releases shipped. The key name is its
        ; product code. /passive shows progress and asks for elevation when a
        ; per-machine install needs it; it waits for no other answer, so a
        ; deployment tool running as SYSTEM is not held. 3010 is success with
        ; a reboot pending, and 1605 means the product is already gone.
        DetailPrint "KlaayGuard: removing the earlier MSI install $R6"
        ExecWait '"$SYSDIR\msiexec.exe" /x $R6 /passive /norestart' $R9
        DetailPrint "KlaayGuard: msiexec exited $R9"
      ${Else}
        ; An NSIS install. /UPDATE keeps the sign-in, the Run value and the
        ; shortcuts, which this install writes again: the uninstallers check it
        ; before --forget-credentials (NSIS_HOOK_PREUNINSTALL), and have since
        ; the first Windows release. _?= runs the uninstaller in place, so
        ; ExecWait waits for it; without it the uninstaller copies itself to
        ; TEMP and returns at once. In place, it cannot delete itself.
        ReadRegStr $R8 ${ROOT} $R7 "InstallLocation"
        ${If} $R8 == ""
          ReadRegStr $R8 ${ROOT} $R7 "UninstallString"
          nsis_tauri_utils::StrReplace "$R8" '"' ""
          Pop $R8
          ${GetParent} "$R8" $R8
        ${Else}
          nsis_tauri_utils::StrReplace "$R8" '"' ""
          Pop $R8
        ${EndIf}
        ReadRegStr $R9 ${ROOT} $R7 "MainBinaryName"
        ${IfThen} $R9 == "" ${|} StrCpy $R9 "${MAINBINARYNAME}.exe" ${|}
        ${If} ${FileExists} "$R8\uninstall.exe"
          DetailPrint "KlaayGuard: removing the earlier install in $R8"
          ExecWait '"$R8\uninstall.exe" /S /UPDATE _?=$R8'
          Delete "$R8\uninstall.exe"
          RMDir "$R8"
        ${EndIf}
        ; An uninstaller removes only the key it was built with. An entry under
        ; another name, or one whose uninstaller is gone, is left to this sweep
        ; once the program itself is gone.
        ${IfNot} ${FileExists} "$R8\$R9"
          DeleteRegKey ${ROOT} $R7
        ${EndIf}
      ${EndIf}

      ; Gone when its name is gone.
      ReadRegStr $R9 ${ROOT} $R7 "DisplayName"
      ${If} $R9 == ""
        StrCpy $R5 0
        ${Continue}
      ${EndIf}
      DetailPrint "KlaayGuard: ERROR the earlier install $R6 is still there"
      IntOp $3 $3 + 1
    ${EndIf}
    IntOp $R5 $R5 + 1
  ${Loop}
!macroend

!macro NSIS_HOOK_PREINSTALL
  ; Remove every earlier install before this one writes a file.
  ;
  ; The template removes an earlier version on one path only: its "already
  ; installed" page, which /S skips. /S is what the self-updater runs and what
  ; every deployment tool runs, so on those paths the files went on top of the
  ; old ones and nothing else was removed. The page also skips an .msi install
  ; once it finds a per-user one, never looks in another folder, and on the
  ; same version defaults to "reinstall", which removes nothing.
  ;
  ; This sweep runs on every path: silent, passive and interactive. It removes
  ; each KlaayGuard entry in Add/Remove Programs, per-user and per-machine, in
  ; both registry views. That covers the install this one replaces, an earlier
  ; install in another folder, and an .msi install. The per-user installs of
  ; other Windows accounts are out of reach: this installer runs as the user,
  ; and their registry hives are not loaded.
  ;
  ; Stop the agent first. An .msi uninstall cannot delete a running .exe; it
  ; schedules the delete for a reboot and reports success. The template's own
  ; check asks the user in an interactive install and stops it otherwise.
  !insertmacro CheckIfAppIsRunning "${MAINBINARYNAME}.exe" "${PRODUCTNAME}"

  Push $3
  Push $R4
  Push $R5
  Push $R6
  Push $R7
  Push $R8
  Push $R9
  StrCpy $3 0

  ; Leave $INSTDIR, so the uninstall of an install in the same folder can
  ; delete it. Windows keeps a process's working directory.
  SetOutPath $TEMP

  !insertmacro KLAAYGUARD_REMOVE_EARLIER_UNDER HKCU
  SetRegView 64
  !insertmacro KLAAYGUARD_REMOVE_EARLIER_UNDER HKLM
  SetRegView 32
  !insertmacro KLAAYGUARD_REMOVE_EARLIER_UNDER HKLM
  ; Back to the view and shell context the template set in .onInit.
  !insertmacro SetContext

  ; Never stop here. Abort would leave a machine whose agent the template is
  ; about to stop with no agent at all, and a management tool would retry into
  ; the same failure. Install, and report it: exit code 1001, like 1000 below.
  ${If} $3 > 0
    SetErrorLevel 1001
    DetailPrint "KlaayGuard: $3 earlier install(s) could not be removed (exit code 1001, see the README)"
    Push $0
    System::Call 'kernel32::AttachConsole(i -1)i.r0'
    ${If} $0 <> 0
      System::Call 'kernel32::GetStdHandle(i -11)i.r0'
      FileWrite $0 "KlaayGuard: $3 earlier install(s) could not be removed (exit code 1001, see the README)$\n"
    ${EndIf}
    Pop $0
  ${EndIf}

  Pop $R9
  Pop $R8
  Pop $R7
  Pop $R6
  Pop $R5
  Pop $R4
  Pop $3

  SetOutPath $INSTDIR
!macroend

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
  ; behind is_production_target. Two agents is PROD-4603, which this repo has
  ; shipped once already.
  ;
  ; RunAsUser starts the agent as the logged-in user, never as the elevated
  ; installer, so the credential store stays with the person at the machine. It
  ; pushes one result: zero for success, one for failure. Read it. An unread
  ; failure is the silent no-agent install this hook exists to prevent.
  ${If} ${Silent}
  ${OrIf} $PassiveMode = 1
    ClearErrors
    ${GetOptions} $CMDLINE "/R" $R9
    ${If} ${Errors}
      nsis_tauri_utils::RunAsUser "$INSTDIR\${MAINBINARYNAME}.exe" ""
      Pop $R9
      ${If} $R9 <> 0
        ; RunAsUser fails on more than one path: a failed shell launch when
        ; the caller is not elevated, and each token step when it is. The one
        ; a deployment meets is an elevated caller with no shell window, which
        ; is a management tool running as SYSTEM in session 0. That caller has
        ; no console for AttachConsole and reads no install log, so the exit
        ; code is the only channel that reaches it.
        ;
        ; SetErrorLevel marks the install and does not abort it. The files are
        ; in place. An abort would leave the machine without them and would
        ; send a management tool into a retry loop. The cause does not clear
        ; on its own, so every retry would fail the same way.
        ;
        ; 1000 is ours, not a Windows Installer code. NSIS uses 0 for success,
        ; 1 for a user abort and 2 for an abort by the script. A tool that
        ; reads it learns the files landed and the agent did not start. Both
        ; this and an abort are non-zero, so a deployment tool still needs the
        ; mapping. The README's "Installer exit code 1000" section gives it.
        ; It also says what the Run value above means for that reader. The
        ; value follows the installing account, so only a user-context install
        ; starts the agent at the next logon.
        SetErrorLevel 1000
        DetailPrint "KlaayGuard: the agent did not start (exit code 1000, see the README)"
        Push $0
        System::Call 'kernel32::AttachConsole(i -1)i.r0'
        ${If} $0 <> 0
          System::Call 'kernel32::GetStdHandle(i -11)i.r0'
          FileWrite $0 "KlaayGuard: the agent did not start (exit code 1000, see the README)$\n"
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
