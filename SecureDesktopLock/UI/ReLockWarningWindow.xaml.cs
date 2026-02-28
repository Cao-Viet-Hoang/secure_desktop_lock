using System;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

namespace SecureDesktopLock.UI
{
    /// <summary>
    /// A small always-on-top overlay that warns the user the lock screen
    /// will reappear in N seconds.
    ///
    /// Positioned at the bottom-right corner of the primary monitor.
    /// Made click-through via <c>WS_EX_TRANSPARENT</c> so the user can
    /// continue working without obstruction.
    /// </summary>
    public partial class ReLockWarningWindow : Window
    {
        // ------------------------------------------------------------------ //
        //  Win32 constants for click-through                                 //
        // ------------------------------------------------------------------ //
        private const int GWL_EXSTYLE = -20;
        private const int WS_EX_TRANSPARENT = 0x00000020;
        private const int WS_EX_TOOLWINDOW = 0x00000080;

        [DllImport("user32.dll", SetLastError = true)]
        private static extern int GetWindowLong(IntPtr hWnd, int nIndex);

        [DllImport("user32.dll")]
        private static extern int SetWindowLong(IntPtr hWnd, int nIndex, int dwNewLong);

        // ------------------------------------------------------------------ //
        //  Constructor                                                        //
        // ------------------------------------------------------------------ //

        public ReLockWarningWindow()
        {
            InitializeComponent();
        }

        // ------------------------------------------------------------------ //
        //  Public API                                                         //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Updates the countdown display.  Must be called on the UI thread.
        /// </summary>
        public void UpdateCountdown(int secondsRemaining)
        {
            int m = secondsRemaining / 60;
            int s = secondsRemaining % 60;
            CountdownText.Text = $"Screen will lock in {m:D2}:{s:D2}";
        }

        // ------------------------------------------------------------------ //
        //  Positioning & click-through                                        //
        // ------------------------------------------------------------------ //

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            PositionBottomRight();
            MakeClickThrough();
        }

        /// <summary>
        /// Places the window at the bottom-right of the primary work area,
        /// respecting the taskbar.
        /// </summary>
        private void PositionBottomRight()
        {
            var workArea = SystemParameters.WorkArea;
            Left = workArea.Right - ActualWidth - 8;
            Top = workArea.Bottom - ActualHeight - 8;
        }

        /// <summary>
        /// Makes the window pass all mouse/touch input through to whatever
        /// is behind it (<c>WS_EX_TRANSPARENT</c>) and hides it from the
        /// Alt-Tab switcher (<c>WS_EX_TOOLWINDOW</c>).
        /// </summary>
        private void MakeClickThrough()
        {
            IntPtr hwnd = new WindowInteropHelper(this).Handle;
            if (hwnd == IntPtr.Zero) return;

            int exStyle = GetWindowLong(hwnd, GWL_EXSTYLE);
            SetWindowLong(hwnd, GWL_EXSTYLE,
                exStyle | WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW);
        }
    }
}
