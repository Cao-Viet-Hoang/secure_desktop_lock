using SecureDesktopLock.Utils;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows.Input;

namespace SecureDesktopLock.Services
{
    /// <summary>
    /// Installs a system-wide (low-level) keyboard hook via the Win32
    /// <c>SetWindowsHookEx(WH_KEYBOARD_LL)</c> API to suppress security-
    /// sensitive key combinations while the desktop lock is active.
    ///
    /// Blocked combinations
    /// --------------------
    ///   • ALT + TAB          — task switcher
    ///   • ALT + F4           — close focused window
    ///   • WIN (left/right)   — Start menu / Action Center
    ///   • CTRL + ESC         — Start menu (legacy)
    ///   • CTRL + SHIFT + ESC — Task Manager
    ///   • CTRL + ALT + DEL   — Secure Attention Sequence (intercepted at
    ///                          kernel level; a best-effort block is applied
    ///                          but Windows may still show the SAS screen)
    ///
    /// Thread safety
    /// -------------
    /// The hook is installed on the calling thread's message queue.  Call
    /// <see cref="Start"/> from the UI thread (or a thread with a message
    /// pump) to ensure hook messages are delivered correctly.
    ///
    /// Cleanup
    /// -------
    /// Always call <see cref="Stop"/> (or <see cref="Dispose"/>) before the
    /// application exits, otherwise the hook will leak until the OS cleans up.
    /// </summary>
    public sealed class KeyboardHookService : IDisposable
    {
        // ------------------------------------------------------------------ //
        //  Win32 constants                                                    //
        // ------------------------------------------------------------------ //
        private const int WH_KEYBOARD_LL = 13;
        private const int WM_KEYDOWN = 0x0100;
        private const int WM_KEYUP = 0x0101;
        private const int WM_SYSKEYDOWN = 0x0104;
        private const int WM_SYSKEYUP = 0x0105;

        // Virtual key codes
        private const int VK_TAB = 0x09;
        private const int VK_F4 = 0x73;
        private const int VK_ESCAPE = 0x1B;
        private const int VK_LWIN = 0x5B;
        private const int VK_RWIN = 0x5C;
        private const int VK_DELETE = 0x2E;

        // LLKHF_ALTDOWN flag in KBDLLHOOKSTRUCT.flags
        private const int LLKHF_ALTDOWN = 0x20;

        // ------------------------------------------------------------------ //
        //  Win32 P/Invoke                                                     //
        // ------------------------------------------------------------------ //
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(
            int idHook,
            LowLevelKeyboardProc lpfn,
            IntPtr hMod,
            uint dwThreadId);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CallNextHookEx(
            IntPtr hhk,
            int nCode,
            IntPtr wParam,
            IntPtr lParam);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("user32.dll")]
        private static extern short GetAsyncKeyState(int vKey);

        // ------------------------------------------------------------------ //
        //  Internal structures                                                //
        // ------------------------------------------------------------------ //
        private delegate IntPtr LowLevelKeyboardProc(
            int nCode, IntPtr wParam, IntPtr lParam);

        [StructLayout(LayoutKind.Sequential)]
        private struct KBDLLHOOKSTRUCT
        {
            public uint vkCode;
            public uint scanCode;
            public uint flags;
            public uint time;
            public IntPtr dwExtraInfo;
        }

        // ------------------------------------------------------------------ //
        //  Fields                                                             //
        // ------------------------------------------------------------------ //
        private IntPtr _hookHandle = IntPtr.Zero;

        // Keep a strong reference to the delegate so the GC doesn't collect it
        // while the hook is active.
        private LowLevelKeyboardProc _hookCallback;

        private bool _disposed;

        // ------------------------------------------------------------------ //
        //  Public members                                                     //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Installs the low-level keyboard hook.  Must be called from a thread
        /// that has a Win32 message loop (e.g. the WPF dispatcher thread).
        /// </summary>
        public void Start()
        {
            if (_hookHandle != IntPtr.Zero) return; // Already installed

            _hookCallback = HookCallback;

            using (Process curProcess = Process.GetCurrentProcess())
            using (ProcessModule curModule = curProcess.MainModule)
            {
                _hookHandle = SetWindowsHookEx(
                    WH_KEYBOARD_LL,
                    _hookCallback,
                    GetModuleHandle(curModule.ModuleName),
                    0); // 0 = all threads (low-level hook is always global)
            }

            if (_hookHandle == IntPtr.Zero)
            {
                int error = Marshal.GetLastWin32Error();
                Logger.LogError($"SetWindowsHookEx failed. Win32 error: {error}");
            }
            else
            {
                Logger.LogInfo("Low-level keyboard hook installed.");
            }
        }

        /// <summary>
        /// Removes the keyboard hook.  Safe to call multiple times.
        /// </summary>
        public void Stop()
        {
            if (_hookHandle == IntPtr.Zero) return;

            if (!UnhookWindowsHookEx(_hookHandle))
            {
                int error = Marshal.GetLastWin32Error();
                Logger.LogWarning($"UnhookWindowsHookEx failed. Win32 error: {error}");
            }
            else
            {
                Logger.LogInfo("Low-level keyboard hook removed.");
            }

            _hookHandle = IntPtr.Zero;
            _hookCallback = null;
        }

        // ------------------------------------------------------------------ //
        //  Hook callback                                                      //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Called by Windows for every key event (all processes) while the
        /// hook is installed.  Returns a non-zero value to suppress the event;
        /// calls CallNextHookEx to forward it to other hooks / the application.
        ///
        /// SECURITY NOTE: Returning non-zero from a low-level hook swallows
        /// the keystroke for all applications.  This is intentional — we want
        /// to prevent the user from switching away from the lock overlay.
        /// </summary>
        private IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            // nCode < 0 means we must pass the message on without processing
            if (nCode < 0)
                return CallNextHookEx(_hookHandle, nCode, wParam, lParam);

            int msg = wParam.ToInt32();
            bool isKeyDown = msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN;

            if (isKeyDown)
            {
                KBDLLHOOKSTRUCT kbStruct =
                    (KBDLLHOOKSTRUCT)Marshal.PtrToStructure(
                        lParam, typeof(KBDLLHOOKSTRUCT));

                uint vk = kbStruct.vkCode;
                bool altDown = (kbStruct.flags & LLKHF_ALTDOWN) != 0;
                bool ctrlDown = (GetAsyncKeyState(0x11) & 0x8000) != 0; // VK_CONTROL

                if (ShouldBlock(vk, altDown, ctrlDown))
                {
                    // Return a dummy non-zero value — convention is 1
                    return (IntPtr)1;
                }
            }

            return CallNextHookEx(_hookHandle, nCode, wParam, lParam);
        }

        /// <summary>
        /// Determines whether a given key event should be suppressed.
        /// Encapsulated here to keep the logic readable and testable.
        /// </summary>
        private static bool ShouldBlock(uint vk, bool altDown, bool ctrlDown)
        {
            // ALT + TAB — task switcher
            if (altDown && vk == VK_TAB) return true;

            // ALT + F4 — close window
            if (altDown && vk == VK_F4) return true;

            // Windows keys (Start menu, Action Center, snap shortcuts …)
            if (vk == VK_LWIN || vk == VK_RWIN) return true;

            // CTRL + ESC — Start menu (old-school)
            if (ctrlDown && vk == VK_ESCAPE) return true;

            // CTRL + SHIFT + ESC — Task Manager
            bool shiftDown = (GetAsyncKeyState(0x10) & 0x8000) != 0; // VK_SHIFT
            if (ctrlDown && shiftDown && vk == VK_ESCAPE) return true;

            // CTRL + ALT + DEL is intercepted by csrss.exe / winlogon at ring-0;
            // we can't fully block it from user-mode.  However, capturing the
            // sequence here prevents legacy software from misinterpreting it.
            if (ctrlDown && altDown && vk == VK_DELETE) return true;

            return false;
        }

        // ------------------------------------------------------------------ //
        //  IDisposable                                                        //
        // ------------------------------------------------------------------ //

        public void Dispose()
        {
            if (_disposed) return;
            Stop();
            _disposed = true;
        }
    }
}
