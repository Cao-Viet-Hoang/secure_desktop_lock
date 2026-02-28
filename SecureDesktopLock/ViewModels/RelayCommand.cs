using System;
using System.Windows.Input;

namespace SecureDesktopLock.ViewModels
{
    /// <summary>
    /// Minimal <see cref="ICommand"/> implementation used throughout the MVVM
    /// layer to bind UI controls to ViewModel actions.
    ///
    /// Supports both synchronous and asynchronous patterns:
    ///   • Pass a plain <c>Action</c> for synchronous commands.
    ///   • Pass an <c>Action</c> that starts an async operation
    ///     (fire-and-forget) for async commands — the ViewModel is responsible
    ///     for managing the resulting task and updating IsEnabled as needed.
    /// </summary>
    public sealed class RelayCommand : ICommand
    {
        private readonly Action<object> _execute;
        private readonly Func<object, bool> _canExecute;

        // ------------------------------------------------------------------ //
        //  Constructors                                                       //
        // ------------------------------------------------------------------ //

        /// <param name="execute">Action to invoke when the command executes.</param>
        /// <param name="canExecute">
        /// Optional predicate.  When <c>null</c>, the command is always enabled.
        /// </param>
        public RelayCommand(Action<object> execute, Func<object, bool> canExecute = null)
        {
            _execute = execute ?? throw new ArgumentNullException(nameof(execute));
            _canExecute = canExecute;
        }

        /// <summary>Convenience constructor for parameter-less actions.</summary>
        public RelayCommand(Action execute, Func<bool> canExecute = null)
            : this(
                  _ => execute(),
                  canExecute == null ? (Func<object, bool>)null : _ => canExecute())
        { }

        // ------------------------------------------------------------------ //
        //  ICommand                                                           //
        // ------------------------------------------------------------------ //

        public bool CanExecute(object parameter) =>
            _canExecute == null || _canExecute(parameter);

        public void Execute(object parameter) => _execute(parameter);

        /// <summary>
        /// Raises <see cref="CanExecuteChanged"/> so that the UI re-evaluates
        /// the enabled state of bound controls.
        /// </summary>
        /// <inheritdoc/>
        /// <remarks>
        /// Wired to the WPF <see cref="CommandManager.RequerySuggested"/> event
        /// so that WPF automatically calls <see cref="CanExecute"/> whenever
        /// user input occurs — without the ViewModel needing to call
        /// <see cref="RaiseCanExecuteChanged"/> explicitly.
        /// </remarks>
        public event EventHandler CanExecuteChanged
        {
            add { CommandManager.RequerySuggested += value; }
            remove { CommandManager.RequerySuggested -= value; }
        }

        /// <summary>
        /// Causes WPF to re-query <see cref="CanExecute"/> on all commands.
        /// </summary>
        public void RaiseCanExecuteChanged() =>
            CommandManager.InvalidateRequerySuggested();
    }
}
