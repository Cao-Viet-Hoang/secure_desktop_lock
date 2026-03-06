using System;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Threading;

namespace SecureDesktopLock.UI
{
    /// <summary>
    /// A small always-on-top toast notification shown at the bottom-right
    /// corner after a successful unlock.
    ///
    /// Displays how many minutes remain until the screen re-locks, plus the
    /// exact clock time at which re-lock will occur.  Dismisses itself
    /// automatically after 5 seconds.
    ///
    /// The window is click-through (<c>WS_EX_TRANSPARENT</c>) so it never
    /// interferes with the user's work.
    /// </summary>
    public partial class UnlockToastWindow : Window
    {
        // ------------------------------------------------------------------ //
        //  Win32 constants for click-through                                 //
        // ------------------------------------------------------------------ //
        private const int GWL_EXSTYLE    = -20;
        private const int WS_EX_TRANSPARENT  = 0x00000020;
        private const int WS_EX_TOOLWINDOW   = 0x00000080;

        [DllImport("user32.dll", SetLastError = true)]
        private static extern int GetWindowLong(IntPtr hWnd, int nIndex);

        [DllImport("user32.dll")]
        private static extern int SetWindowLong(IntPtr hWnd, int nIndex, int dwNewLong);

        // ------------------------------------------------------------------ //
        //  Fields                                                             //
        // ------------------------------------------------------------------ //
        private DispatcherTimer _timer;
        private int _ticksRemaining;      // 50 ticks × 100 ms = 5 s
        private double _barFullWidth;     // captured after layout

        private const int TotalTicks = 50;      // 5 000 ms / 100 ms
        private const int TickIntervalMs = 100;

        // ------------------------------------------------------------------ //
        //  Constructor                                                        //
        // ------------------------------------------------------------------ //

        public UnlockToastWindow()
        {
            InitializeComponent();
        }

        // ------------------------------------------------------------------ //
        //  Public API                                                         //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Populates the toast with relock information and starts the
        /// 5-second auto-dismiss countdown.
        ///
        /// Call this <em>before</em> or <em>after</em> <see cref="Show"/>
        /// (both orderings are safe).
        /// </summary>
        /// <param name="relockIntervalSeconds">
        /// The re-lock interval in seconds as returned by
        /// <c>ReLockService.StartAsync</c>.  Pass 0 to show a generic
        /// "unlocked" message without relock time info.
        /// </param>
        public void SetRelockInfo(int relockIntervalSeconds)
        {
            if (relockIntervalSeconds > 0)
            {
                int minutes = relockIntervalSeconds / 60;
                int seconds = relockIntervalSeconds % 60;
                DateTime relockAt = DateTime.Now.AddSeconds(relockIntervalSeconds);

                string minuteLabel = minutes == 1 ? "minute" : "minutes";
                TitleText.Text = minutes > 0
                    ? $"Re-locks in {minutes} {minuteLabel} (at {relockAt:HH:mm})"
                    : $"Re-locks in {seconds}s (at {relockAt:HH:mm:ss})";

                SubText.Text   = $"Session active until {relockAt:HH:mm}";
                SubText.Visibility = Visibility.Visible;
            }
            else
            {
                TitleText.Text     = "Unlocked successfully";
                SubText.Visibility = Visibility.Collapsed;
            }
        }

        // ------------------------------------------------------------------ //
        //  Window lifecycle                                                   //
        // ------------------------------------------------------------------ //

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            // Layout must be complete before we can read ActualWidth
            UpdateLayout();

            PositionBottomRight();
            MakeClickThrough();
            StartCountdown();
        }

        // ------------------------------------------------------------------ //
        //  Countdown timer                                                    //
        // ------------------------------------------------------------------ //

        private void StartCountdown()
        {
            // Capture the full width of the progress fill rectangle
            _barFullWidth = TimerFill.ActualWidth > 0
                ? TimerFill.ActualWidth
                : TimerFill.Width;  // fallback to the design-time value

            _ticksRemaining = TotalTicks;

            _timer = new DispatcherTimer
            {
                Interval = TimeSpan.FromMilliseconds(TickIntervalMs)
            };
            _timer.Tick += OnTimerTick;
            _timer.Start();
        }

        private void OnTimerTick(object sender, EventArgs e)
        {
            _ticksRemaining--;

            // Shrink the progress bar proportionally
            double ratio = Math.Max(0.0, (double)_ticksRemaining / TotalTicks);
            TimerFill.Width = _barFullWidth * ratio;

            if (_ticksRemaining <= 0)
            {
                _timer.Stop();
                Close();
            }
        }

        // ------------------------------------------------------------------ //
        //  Positioning & click-through                                        //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Places the toast at the bottom-right of the primary work area,
        /// respecting the taskbar.
        /// </summary>
        private void PositionBottomRight()
        {
            var workArea = SystemParameters.WorkArea;
            Left = workArea.Right  - ActualWidth  - 8;
            Top  = workArea.Bottom - ActualHeight - 8;
        }

        /// <summary>
        /// Makes the window pass all mouse/touch input through to whatever
        /// is behind it and hides it from the Alt-Tab switcher.
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
