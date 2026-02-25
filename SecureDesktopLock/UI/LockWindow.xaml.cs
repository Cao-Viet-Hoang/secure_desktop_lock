using SecureDesktopLock.ViewModels;
using System;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Input;
using System.Windows.Interop;

namespace SecureDesktopLock.UI
{
    /// <summary>
    /// Code-behind for the fullscreen lock overlay window.
    ///
    /// Responsibilities of this class (View layer):
    ///   • Apply window-level security hardening after the window is shown
    ///     (remove the close button, extend WS_EX_TOPMOST style aggressively).
    ///   • Forward the PasswordBox's SecureString to the ViewModel command
    ///     on button click so the ViewModel never touches the PasswordBox directly.
    ///   • Suppress Alt+F4 / window close at the WPF level as a secondary
    ///     layer of defence (the KeyboardHookService operates at the system level).
    ///   • Respond to the ViewModel's UnlockSucceeded event and close gracefully.
    /// </summary>
    public partial class LockWindow : Window
    {
        // ------------------------------------------------------------------ //
        //  Win32 P/Invoke – window style manipulation                        //
        // ------------------------------------------------------------------ //
        private const int GWL_STYLE = -16;
        private const int GWL_EXSTYLE = -20;
        private const int WS_SYSMENU = 0x00080000;

        /// <summary>
        /// Extended window style: makes the window topmost and tool-window
        /// (no taskbar entry).  TOPMOST is already set via XAML; enforcing
        /// it here via native API is a belt-and-braces measure.
        /// </summary>
        private const int WS_EX_TOPMOST = 0x00000008;
        private const int WS_EX_TOOLWINDOW = 0x00000080;

        [DllImport("user32.dll", SetLastError = true)]
        private static extern int GetWindowLong(IntPtr hWnd, int nIndex);

        [DllImport("user32.dll")]
        private static extern int SetWindowLong(IntPtr hWnd, int nIndex, int dwNewLong);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetWindowPos(
            IntPtr hWnd, IntPtr hWndInsertAfter,
            int X, int Y, int cx, int cy, uint uFlags);

        private static readonly IntPtr HWND_TOPMOST = new IntPtr(-1);
        private const uint SWP_NOMOVE = 0x0002;
        private const uint SWP_NOSIZE = 0x0001;
        private const uint SWP_SHOWWINDOW = 0x0040;

        // ------------------------------------------------------------------ //
        //  Fields                                                             //
        // ------------------------------------------------------------------ //
        private LockViewModel _viewModel;
        private bool _allowClose = false; // gate that prevents accidental close

        // ------------------------------------------------------------------ //
        //  Constructor                                                        //
        // ------------------------------------------------------------------ //

        public LockWindow()
        {
            InitializeComponent();
        }

        /// <summary>
        /// Attaches the ViewModel and subscribes to its events.
        /// Called by <c>App.xaml.cs</c> after constructing the window.
        /// </summary>
        public void SetViewModel(LockViewModel viewModel)
        {
            _viewModel = viewModel
                ?? throw new ArgumentNullException(nameof(viewModel));

            DataContext = _viewModel;

            // Listen for successful authentication
            _viewModel.UnlockSucceeded += OnUnlockSucceeded;
        }

        // ------------------------------------------------------------------ //
        //  Event handlers                                                    //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Applies Win32-level window hardening once the HWND exists.
        /// Called after the window has been fully rendered for the first time.
        /// </summary>
        private void LockWindow_Loaded(object sender, RoutedEventArgs e)
        {
            ApplyWindowHardening();

            // Auto-focus the password box for immediate keyboard input
            PasswordInput.Focus();
        }

        /// <summary>
        /// Prevents the window from being closed by any means except the
        /// <see cref="_allowClose"/> gate (set only on successful unlock).
        /// </summary>
        private void LockWindow_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            if (!_allowClose)
            {
                e.Cancel = true; // Swallow the close request
            }
        }

        /// <summary>
        /// Secondary keyboard handler at the WPF level.
        /// The system-level hook (<see cref="KeyboardHookService"/>) is the
        /// primary defence; this handles any residual edge cases within WPF.
        /// </summary>
        private void LockWindow_KeyDown(object sender, KeyEventArgs e)
        {
            // Suppress Escape — prevents accidental focus loss to dialogs
            if (e.Key == Key.Escape)
            {
                e.Handled = true;
                return;
            }

            // Re-assert topmost on any key press (defence against Win key presses
            // that briefly show the Start menu before the hook suppresses them)
            EnsureTopmost();
        }

        /// <summary>
        /// Triggered by the Unlock button click.
        /// Passes the PasswordBox's <see cref="System.Security.SecureString"/>
        /// to the ViewModel command so plain-text never leaves this method.
        /// </summary>
        private void UnlockButton_Click(object sender, RoutedEventArgs e)
        {
            if (_viewModel?.UnlockCommand?.CanExecute(PasswordInput.SecurePassword) == true)
            {
                _viewModel.UnlockCommand.Execute(PasswordInput.SecurePassword);
            }

            // Clear and re-focus so the user can retry without selecting text
            PasswordInput.Clear();
            PasswordInput.Focus();
        }

        // ------------------------------------------------------------------ //
        //  Unlock success                                                     //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Called (on the UI thread) when the ViewModel fires
        /// <c>UnlockSucceeded</c>.  Opens the gate and closes the window.
        /// </summary>
        private void OnUnlockSucceeded(object sender, EventArgs e)
        {
            _allowClose = true;
            Close();
        }

        // ------------------------------------------------------------------ //
        //  Win32 hardening helpers                                           //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Removes the system-menu (which contains the Close option) and
        /// forces the window to remain above all others via SetWindowPos.
        /// Must be called after the HWND has been created (i.e. from Loaded).
        /// </summary>
        private void ApplyWindowHardening()
        {
            IntPtr hwnd = new WindowInteropHelper(this).Handle;
            if (hwnd == IntPtr.Zero) return;

            // Remove system menu → removes Close/Minimise/Maximise items
            int style = GetWindowLong(hwnd, GWL_STYLE);
            SetWindowLong(hwnd, GWL_STYLE, style & ~WS_SYSMENU);

            // Remove from taskbar + Alt-Tab switcher via WS_EX_TOOLWINDOW
            int exStyle = GetWindowLong(hwnd, GWL_EXSTYLE);
            SetWindowLong(hwnd, GWL_EXSTYLE,
                (exStyle | WS_EX_TOPMOST | WS_EX_TOOLWINDOW));

            // Enforce HWND_TOPMOST position
            SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
        }

        /// <summary>
        /// Re-asserts HWND_TOPMOST without resizing or moving.
        /// Called on every keypress as a low-cost defence layer.
        /// </summary>
        private void EnsureTopmost()
        {
            IntPtr hwnd = new WindowInteropHelper(this).Handle;
            if (hwnd == IntPtr.Zero) return;

            SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0,
                SWP_NOMOVE | SWP_NOSIZE);
        }
    }
}
