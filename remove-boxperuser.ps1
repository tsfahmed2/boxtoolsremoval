
function Execute-AsLoggedOnUser($Command,$Hidden=$true) {
    <#
    .SYNOPSIS
    Function that can execute powershell in the context of the logged-in user.
    .DESCRIPTION
    This function will use advanced API's to get the access token of the currently logged-in user, in order to execute a script in the users context.
    This is useful for scripts that are run in the local system users context.
    .REQUIREMENTS
    This script myst be run from the context of the SYSTEM account.
    Designes to be run by Intune or SCCM Agent.
    Absolute paths required.
    .EXAMPLE
    Running a powershell script visible to the user
        $userCommand = '-file c:\windows\temp\script.ps1'
        executeAsLoggedOnUser -Command $userCommand -Hidden $false
    .EXAMPLE
    Running a powershell command hidden from the user (hidden is default true)
        $userCommand = '-command &{remove-item c:\temp\secretfile.txt}'
        executeAsLoggedOnUser -Command $userCommand
    .COPYRIGHT
    MIT License, feel free to distribute and use as you like, please leave author information.
    .AUTHOR
    Michael Mardahl - @michael_mardahl on twitter - BLOG: https://www.iphase.dk
    C# borrowed from the awesome Justin Myrray (https://github.com/murrayju/CreateProcessAsUser)
    .DISCLAIMER
    This function is provided AS-IS, with no warranty - Use at own risk!
    #>

$csharpCode = @"
    using System;  
    using System.Runtime.InteropServices;

    namespace murrayju.ProcessExtensions  
    {
        public static class ProcessExtensions
        {
            #region Win32 Constants

            private const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;
            private const int CREATE_NO_WINDOW = 0x08000000;

            private const int CREATE_NEW_CONSOLE = 0x00000010;

            private const uint INVALID_SESSION_ID = 0xFFFFFFFF;
            private static readonly IntPtr WTS_CURRENT_SERVER_HANDLE = IntPtr.Zero;

            #endregion

            #region DllImports

            [DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUser", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
            private static extern bool CreateProcessAsUser(
                IntPtr hToken,
                String lpApplicationName,
                String lpCommandLine,
                IntPtr lpProcessAttributes,
                IntPtr lpThreadAttributes,
                bool bInheritHandle,
                uint dwCreationFlags,
                IntPtr lpEnvironment,
                String lpCurrentDirectory,
                ref STARTUPINFO lpStartupInfo,
                out PROCESS_INFORMATION lpProcessInformation);

            [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
            private static extern bool DuplicateTokenEx(
                IntPtr ExistingTokenHandle,
                uint dwDesiredAccess,
                IntPtr lpThreadAttributes,
                int TokenType,
                int ImpersonationLevel,
                ref IntPtr DuplicateTokenHandle);

            [DllImport("userenv.dll", SetLastError = true)]
            private static extern bool CreateEnvironmentBlock(ref IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

            [DllImport("userenv.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

            [DllImport("kernel32.dll", SetLastError = true)]
            private static extern bool CloseHandle(IntPtr hSnapshot);

            [DllImport("kernel32.dll")]
            private static extern uint WTSGetActiveConsoleSessionId();

            [DllImport("Wtsapi32.dll")]
            private static extern uint WTSQueryUserToken(uint SessionId, ref IntPtr phToken);

            [DllImport("wtsapi32.dll", SetLastError = true)]
            private static extern int WTSEnumerateSessions(
                IntPtr hServer,
                int Reserved,
                int Version,
                ref IntPtr ppSessionInfo,
                ref int pCount);

            #endregion

            #region Win32 Structs

            private enum SW
            {
                SW_HIDE = 0,
                SW_SHOWNORMAL = 1,
                SW_NORMAL = 1,
                SW_SHOWMINIMIZED = 2,
                SW_SHOWMAXIMIZED = 3,
                SW_MAXIMIZE = 3,
                SW_SHOWNOACTIVATE = 4,
                SW_SHOW = 5,
                SW_MINIMIZE = 6,
                SW_SHOWMINNOACTIVE = 7,
                SW_SHOWNA = 8,
                SW_RESTORE = 9,
                SW_SHOWDEFAULT = 10,
                SW_MAX = 10
            }

            private enum WTS_CONNECTSTATE_CLASS
            {
                WTSActive,
                WTSConnected,
                WTSConnectQuery,
                WTSShadow,
                WTSDisconnected,
                WTSIdle,
                WTSListen,
                WTSReset,
                WTSDown,
                WTSInit
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct PROCESS_INFORMATION
            {
                public IntPtr hProcess;
                public IntPtr hThread;
                public uint dwProcessId;
                public uint dwThreadId;
            }

            private enum SECURITY_IMPERSONATION_LEVEL
            {
                SecurityAnonymous = 0,
                SecurityIdentification = 1,
                SecurityImpersonation = 2,
                SecurityDelegation = 3,
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct STARTUPINFO
            {
                public int cb;
                public String lpReserved;
                public String lpDesktop;
                public String lpTitle;
                public uint dwX;
                public uint dwY;
                public uint dwXSize;
                public uint dwYSize;
                public uint dwXCountChars;
                public uint dwYCountChars;
                public uint dwFillAttribute;
                public uint dwFlags;
                public short wShowWindow;
                public short cbReserved2;
                public IntPtr lpReserved2;
                public IntPtr hStdInput;
                public IntPtr hStdOutput;
                public IntPtr hStdError;
            }

            private enum TOKEN_TYPE
            {
                TokenPrimary = 1,
                TokenImpersonation = 2
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct WTS_SESSION_INFO
            {
                public readonly UInt32 SessionID;

                [MarshalAs(UnmanagedType.LPStr)]
                public readonly String pWinStationName;

                public readonly WTS_CONNECTSTATE_CLASS State;
            }

            #endregion

            // Gets the user token from the currently active session
            private static bool GetSessionUserToken(ref IntPtr phUserToken)
            {
                var bResult = false;
                var hImpersonationToken = IntPtr.Zero;
                var activeSessionId = INVALID_SESSION_ID;
                var pSessionInfo = IntPtr.Zero;
                var sessionCount = 0;

                // Get a handle to the user access token for the current active session.
                if (WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, ref pSessionInfo, ref sessionCount) != 0)
                {
                    var arrayElementSize = Marshal.SizeOf(typeof(WTS_SESSION_INFO));
                    var current = pSessionInfo;

                    for (var i = 0; i < sessionCount; i++)
                    {
                        var si = (WTS_SESSION_INFO)Marshal.PtrToStructure((IntPtr)current, typeof(WTS_SESSION_INFO));
                        current += arrayElementSize;

                        if (si.State == WTS_CONNECTSTATE_CLASS.WTSActive)
                        {
                            activeSessionId = si.SessionID;
                        }
                    }
                }

                // If enumerating did not work, fall back to the old method
                if (activeSessionId == INVALID_SESSION_ID)
                {
                    activeSessionId = WTSGetActiveConsoleSessionId();
                }

                if (WTSQueryUserToken(activeSessionId, ref hImpersonationToken) != 0)
                {
                    // Convert the impersonation token to a primary token
                    bResult = DuplicateTokenEx(hImpersonationToken, 0, IntPtr.Zero,
                        (int)SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, (int)TOKEN_TYPE.TokenPrimary,
                        ref phUserToken);

                    CloseHandle(hImpersonationToken);
                }

                return bResult;
            }

            public static bool StartProcessAsCurrentUser(string cmdLine, bool visible, string appPath = null, string workDir = null)
            {
                var hUserToken = IntPtr.Zero;
                var startInfo = new STARTUPINFO();
                var procInfo = new PROCESS_INFORMATION();
                var pEnv = IntPtr.Zero;
                int iResultOfCreateProcessAsUser;

                startInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));

                try
                {
                    if (!GetSessionUserToken(ref hUserToken))
                    {
                        throw new Exception("StartProcessAsCurrentUser: GetSessionUserToken failed.");
                    }

                    uint dwCreationFlags = CREATE_UNICODE_ENVIRONMENT | (uint)(visible ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW);
                    startInfo.wShowWindow = (short)(visible ? SW.SW_SHOW : SW.SW_HIDE);
                    startInfo.lpDesktop = "winsta0\\default";

                    if (!CreateEnvironmentBlock(ref pEnv, hUserToken, false))
                    {
                        throw new Exception("StartProcessAsCurrentUser: CreateEnvironmentBlock failed.");
                    }

                    if (!CreateProcessAsUser(hUserToken,
                        appPath, // Application Name
                        cmdLine, // Command Line
                        IntPtr.Zero,
                        IntPtr.Zero,
                        false,
                        dwCreationFlags,
                        pEnv,
                        workDir, // Working directory
                        ref startInfo,
                        out procInfo))
                    {
                        throw new Exception("StartProcessAsCurrentUser: CreateProcessAsUser failed.\n");
                    }

                    iResultOfCreateProcessAsUser = Marshal.GetLastWin32Error();
                }
                finally
                {
                    CloseHandle(hUserToken);
                    if (pEnv != IntPtr.Zero)
                    {
                        DestroyEnvironmentBlock(pEnv);
                    }
                    CloseHandle(procInfo.hThread);
                    CloseHandle(procInfo.hProcess);
                }
                return true;
            }
        }
    }
"@
    # Compiling the source code as csharp
    $compilerParams = [System.CodeDom.Compiler.CompilerParameters]::new()
    $compilerParams.ReferencedAssemblies.AddRange(('System.Runtime.InteropServices.dll', 'System.dll'))
    $compilerParams.CompilerOptions = '/unsafe'
    $compilerParams.GenerateInMemory = $True
    Add-Type -TypeDefinition $csharpCode -Language CSharp -CompilerParameters $compilerParams
    # Adding powershell executeable to the command
    $Command = '{0}\System32\WindowsPowerShell\v1.0\powershell.exe -executionPolicy bypass {1}' -f $($env:windir),$Command
    # Adding double slashes to the command paths, as this is required.
    $Command = $Command.Replace("\","\\")
    # Execute a process as the currently logged on user. 
    # Absolute paths required if running as SYSTEM!
    if($Hidden) { #running the command hidden
        $runCommand = [murrayju.ProcessExtensions.ProcessExtensions]::StartProcessAsCurrentUser($Command,$false)
    }else{ #running the command visible
        $runCommand = [murrayju.ProcessExtensions.ProcessExtensions]::StartProcessAsCurrentUser($Command,$true)
    }

    if ($runCommand) {
        return "Executed `"$Command`" as loggedon user"
    } else {
        throw "Something went wrong when executing process as currently logged-on user"
    }
}


<#
.SYNOPSIS
	Get-InstalledSoftware retrieves a list of installed software
.DESCRIPTION
	Get-InstalledSoftware opens up the specified (remote) registry and scours it for installed software. When found it returns a list of the software and it's version.
.PARAMETER ComputerName
	The computer from which you want to get a list of installed software. Defaults to the local host.
.EXAMPLE
	Get-InstalledSoftware DC1
	
	This will return a list of software from DC1. Like:
	Name			Version		Computer  UninstallCommand
	----			-------     --------  ----------------
	7-Zip 			9.20.00.0	DC1       MsiExec.exe /I{23170F69-40C1-2702-0920-000001000000}
	Google Chrome	65.119.95	DC1       MsiExec.exe /X{6B50D4E7-A873-3102-A1F9-CD5B17976208}
	Opera			12.16		DC1		  "C:\Program Files (x86)\Opera\Opera.exe" /uninstall
.EXAMPLE
	Import-Module ActiveDirectory
	Get-ADComputer -filter 'name -like "DC*"' | Get-InstalledSoftware
	
	This will get a list of installed software on every AD computer that matches the AD filter (So all computers with names starting with DC)
.INPUTS
	[string[]]Computername
.OUTPUTS
	PSObject with properties: Name,Version,Computer,UninstallCommand
.NOTES
	Author: ThePoShWolf
	
	To add registry directories, add to the lmKeys (LocalMachine)
.LINK
	[Microsoft.Win32.RegistryHive]
    [Microsoft.Win32.RegistryKey]
    https://github.com/theposhwolf/utilities
#>
Function Get-InstalledSoftware {
    Param(
        [Alias('Computer','ComputerName','HostName')]
        [Parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$true,Mandatory=$false,Position=1)]
        [string[]]$Name = $env:COMPUTERNAME
    )
    Begin{
        $lmKeys = "Software\Microsoft\Windows\CurrentVersion\Uninstall","SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        $lmReg = [Microsoft.Win32.RegistryHive]::LocalMachine
        $cuKeys = "Software\Microsoft\Windows\CurrentVersion\Uninstall"
        $cuReg = [Microsoft.Win32.RegistryHive]::CurrentUser
    }
    Process{
        if (!(Test-Connection -ComputerName $Name -count 1 -quiet)) {
            Write-Error -Message "Unable to contact $Name. Please verify its network connectivity and try again." -Category ObjectNotFound -TargetObject $Computer
            Break
        }
        $masterKeys = @()
        $remoteCURegKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($cuReg,$Name)
        $remoteLMRegKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($lmReg,$Name)
        foreach ($key in $lmKeys) {
            $regKey = $remoteLMRegKey.OpenSubkey($key)
            foreach ($subName in $regKey.GetSubkeyNames()) {
                foreach($sub in $regKey.OpenSubkey($subName)) {
                    $masterKeys += (New-Object PSObject -Property @{
                        "ComputerName" = $Name
                        "Name" = $sub.GetValue("displayname")
                        "SystemComponent" = $sub.GetValue("systemcomponent")
                        "ParentKeyName" = $sub.GetValue("parentkeyname")
                        "Version" = $sub.GetValue("DisplayVersion")
                        "UninstallCommand" = $sub.GetValue("UninstallString")
                        "InstallDate" = $sub.GetValue("InstallDate")
                        "RegPath" = $sub.ToString()
                    })
                }
            }
        }
        foreach ($key in $cuKeys) {
            $regKey = $remoteCURegKey.OpenSubkey($key)
            if ($regKey -ne $null) {
                foreach ($subName in $regKey.getsubkeynames()) {
                    foreach ($sub in $regKey.opensubkey($subName)) {
                        $masterKeys += (New-Object PSObject -Property @{
                            "ComputerName" = $Computer
                            "Name" = $sub.GetValue("displayname")
                            "SystemComponent" = $sub.GetValue("systemcomponent")
                            "ParentKeyName" = $sub.GetValue("parentkeyname")
                            "Version" = $sub.GetValue("DisplayVersion")
                            "UninstallCommand" = $sub.GetValue("UninstallString")
                            "InstallDate" = $sub.GetValue("InstallDate")
                            "RegPath" = $sub.ToString()
                        })
                    }
                }
            }
        }
        $woFilter = {$null -ne $_.name -AND $_.SystemComponent -ne "1" -AND $null -eq $_.ParentKeyName}
        $props = 'Name','Version','ComputerName','Installdate','UninstallCommand','RegPath'
        $masterKeys = ($masterKeys | Where-Object $woFilter | Select-Object $props | Sort-Object Name)
        $masterKeys
    }
    End{}
}

$boxtoolsuninstallcommand = (Get-InstalledSoftware | where { $_.Name -match "Box Tools"}).UninstallCommand

$boxtoolsuninstallcommand = $boxtoolsuninstallcommand.Trim()
$boxtoolsuninstallcommand = $boxtoolsuninstallcommand -Replace "msiexec.exe","" -Replace "/I","" -Replace "/X",""
$boxtoolsuninstallcommand = $boxtoolsuninstallcommand.Trim()
$boxtoolsuninstallcommand = "/X " + $boxtoolsuninstallcommand + " /quiet"
Write-Host $boxtoolsuninstallcommand
$uninstall = "-command & {Start-Process 'msiexec.exe' -ArgumentList '$boxtoolsuninstallcommand' -Wait}"

#$uninstall = "start-process msiexec $boxtoolsuninstallcommand"
Execute-AsLoggedOnUser -Command $uninstall
Write-Host "Removed old box tools"
