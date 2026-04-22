using System.Diagnostics;
using NosCore.PacketLogger.Models;
using NosCore.PacketLogger.Services;

namespace NosCore.PacketLogger.Forms;

public sealed class MainForm : Form
{
    private readonly SettingsService _settingsService;
    private readonly ProcessService _processService;
    private readonly IInjectionService _injection;
    private readonly PacketLogService _log;
    private AppSettings _settings;

    private readonly ToolStripStatusLabel _statusLabel = new() { Text = "No process attached." };
    private readonly ListBox _logListBox = new();
    private readonly CheckBox _captureSendBox = new() { Text = "Capture Send", AutoSize = true };
    private readonly CheckBox _captureRecvBox = new() { Text = "Capture Recv", AutoSize = true };
    private readonly Button _clearButton = new() { Text = "Clear", AutoSize = true };
    private readonly Button _filtersButton = new() { Text = "Filters…", AutoSize = true };
    private readonly TextBox _injectTextBox = new() { Dock = DockStyle.Fill, PlaceholderText = "Custom packet..." };
    private readonly Button _injectSendButton = new() { Text = "Send", AutoSize = true };
    private readonly Button _injectRecvButton = new() { Text = "Recv", AutoSize = true };

    public MainForm(
        SettingsService settingsService,
        ProcessService processService,
        IInjectionService injection,
        PacketLogService log)
    {
        _settingsService = settingsService;
        _processService = processService;
        _injection = injection;
        _log = log;
        _settings = _settingsService.Load();

        Text = "NosCore.PacketLogger";
        MinimumSize = new Size(520, 360);
        StartPosition = FormStartPosition.Manual;
        TryLoadEmbeddedIcon();
        ApplyWindowStateFromSettings();

        BuildMenu();
        BuildStatusStrip();
        BuildTabs();
        WireEvents();
    }

    private void TryLoadEmbeddedIcon()
    {
        try
        {
            using var stream = typeof(MainForm).Assembly
                .GetManifestResourceStream("NosCore.PacketLogger.logger.ico");
            if (stream is not null)
            {
                Icon = new Icon(stream);
            }
        }
        catch
        {
            // Fall back to the default WinForms icon — not worth blocking startup.
        }
    }

    private void ApplyWindowStateFromSettings()
    {
        Size = new Size(
            Math.Max(MinimumSize.Width, _settings.MainWindow.Width),
            Math.Max(MinimumSize.Height, _settings.MainWindow.Height));
        if (_settings.MainWindow.X >= 0 && _settings.MainWindow.Y >= 0)
        {
            Location = new Point(_settings.MainWindow.X, _settings.MainWindow.Y);
        }
        else
        {
            StartPosition = FormStartPosition.CenterScreen;
        }
    }

    private void BuildMenu()
    {
        var menu = new MenuStrip();
        var fileMenu = new ToolStripMenuItem("&File");
        var selectProcess = new ToolStripMenuItem("&Select process...") { ShortcutKeys = Keys.Control | Keys.P };
        selectProcess.Click += (_, _) => SelectProcess();
        var detach = new ToolStripMenuItem("&Detach") { ShortcutKeys = Keys.Control | Keys.D };
        detach.Click += async (_, _) => await _injection.DetachAsync();
        var exit = new ToolStripMenuItem("E&xit");
        exit.Click += (_, _) => Close();
        fileMenu.DropDownItems.AddRange(new ToolStripItem[] { selectProcess, detach, new ToolStripSeparator(), exit });
        menu.Items.Add(fileMenu);
        MainMenuStrip = menu;
        Controls.Add(menu);
    }

    private void BuildStatusStrip()
    {
        var strip = new StatusStrip();
        strip.Items.Add(_statusLabel);
        Controls.Add(strip);
    }

    private void BuildTabs()
    {
        var tabs = new TabControl
        {
            Dock = DockStyle.Fill,
            Alignment = TabAlignment.Top,
        };
        tabs.TabPages.Add(BuildPacketsTab());
        tabs.TabPages.Add(BuildClientCreatorTab());
        tabs.TabPages.Add(BuildAboutTab());
        Controls.Add(tabs);
        tabs.BringToFront();
    }

    private TabPage BuildPacketsTab()
    {
        var page = new TabPage("Packets");

        _logListBox.Dock = DockStyle.Fill;
        _logListBox.IntegralHeight = false;
        _logListBox.Font = new Font(FontFamily.GenericMonospace, 9F);
        _logListBox.HorizontalScrollbar = true;
        _logListBox.SelectionMode = SelectionMode.MultiExtended;
        _logListBox.KeyDown += OnLogKeyDown;
        _logListBox.ContextMenuStrip = BuildLogContextMenu();

        var toolbar = new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            Padding = new Padding(4),
        };

        _captureSendBox.Checked = _settings.PacketFilters.CaptureSend;
        _captureRecvBox.Checked = _settings.PacketFilters.CaptureReceive;

        _captureSendBox.CheckedChanged += (_, _) =>
        {
            _settings.PacketFilters.CaptureSend = _captureSendBox.Checked;
            Persist();
        };
        _captureRecvBox.CheckedChanged += (_, _) =>
        {
            _settings.PacketFilters.CaptureReceive = _captureRecvBox.Checked;
            Persist();
        };
        _clearButton.Click += (_, _) => _log.Clear();
        _filtersButton.Click += (_, _) => OpenFilters();

        toolbar.Controls.Add(_captureSendBox);
        toolbar.Controls.Add(_captureRecvBox);
        toolbar.Controls.Add(new Label { Text = "   ", AutoSize = true });
        toolbar.Controls.Add(_filtersButton);
        toolbar.Controls.Add(_clearButton);

        var injectBar = BuildInjectBar();

        page.Controls.Add(_logListBox);
        page.Controls.Add(injectBar);
        page.Controls.Add(toolbar);
        return page;
    }

    private Control BuildInjectBar()
    {
        var row = new TableLayoutPanel
        {
            Dock = DockStyle.Bottom,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            ColumnCount = 3,
            RowCount = 1,
            Padding = new Padding(4),
        };
        row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        row.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        row.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

        _injectTextBox.KeyDown += (_, e) =>
        {
            if (e.KeyCode == Keys.Enter)
            {
                _injectSendButton.PerformClick();
                e.SuppressKeyPress = true;
            }
        };
        _injectSendButton.Click += (_, _) => Inject(PacketDirection.Send);
        _injectRecvButton.Click += (_, _) => Inject(PacketDirection.Receive);

        row.Controls.Add(_injectTextBox, 0, 0);
        row.Controls.Add(_injectSendButton, 1, 0);
        row.Controls.Add(_injectRecvButton, 2, 0);

        return row;
    }

    private void Inject(PacketDirection direction)
    {
        var payload = _injectTextBox.Text;
        if (string.IsNullOrWhiteSpace(payload)) return;
        var ok = _injection.InjectPacket(direction, PacketConnection.World, payload);
        if (!ok)
        {
            _statusLabel.Text = "Inject failed — not attached, or no context captured yet.";
        }
    }

    private void OpenFilters()
    {
        using var dialog = new FilterForm(_settings.PacketFilters);
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        _settings.PacketFilters = dialog.Result;
        // Propagate the capture toggles back since the dialog doesn't touch them,
        // but its cloning reset them to the pre-dialog snapshot — refresh explicitly.
        _settings.PacketFilters.CaptureSend = _captureSendBox.Checked;
        _settings.PacketFilters.CaptureReceive = _captureRecvBox.Checked;
        Persist();
    }

    private bool ShouldCapture(LoggedPacket packet)
    {
        if (packet.Direction == PacketDirection.Send && !_settings.PacketFilters.CaptureSend) return false;
        if (packet.Direction == PacketDirection.Receive && !_settings.PacketFilters.CaptureReceive) return false;

        var (filter, isWhitelist) = packet.Direction == PacketDirection.Send
            ? (_settings.PacketFilters.SendFilter, _settings.PacketFilters.SendFilterIsWhitelist)
            : (_settings.PacketFilters.ReceiveFilter, _settings.PacketFilters.ReceiveFilterIsWhitelist);

        if (filter.Count == 0) return true;

        var matches = filter.Any(t => string.Equals(t, packet.Header, StringComparison.OrdinalIgnoreCase));
        return isWhitelist ? matches : !matches;
    }


    private TabPage BuildClientCreatorTab()
    {
        var page = new TabPage("Client creator");

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 3,
            RowCount = 5,
            Padding = new Padding(10),
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        for (var i = 0; i < 5; i++) layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        var newAddressBox = new TextBox { Dock = DockStyle.Fill, PlaceholderText = "e.g. 192.168.1.50" };
        var exeBox = new TextBox { Dock = DockStyle.Fill, ReadOnly = true };
        var outputNameBox = new TextBox { Dock = DockStyle.Fill, PlaceholderText = "(auto-filled once you pick an exe)" };
        var browseButton = new Button { Text = "Browse…", AutoSize = true };
        var patchButton = new Button { Text = "Patch", AutoSize = true };
        var logBox = new TextBox
        {
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Vertical,
            Dock = DockStyle.Fill,
            Font = new Font(FontFamily.GenericMonospace, 9F),
            Height = 160,
        };

        layout.Controls.Add(new Label { Text = "New address:", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 0);
        layout.Controls.Add(newAddressBox, 1, 0);
        layout.SetColumnSpan(newAddressBox, 2);

        layout.Controls.Add(new Label { Text = "Client exe:", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 1);
        layout.Controls.Add(exeBox, 1, 1);
        layout.Controls.Add(browseButton, 2, 1);

        layout.Controls.Add(new Label { Text = "Output file:", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 2);
        layout.Controls.Add(outputNameBox, 1, 2);
        layout.SetColumnSpan(outputNameBox, 2);

        var buttonRow = new FlowLayoutPanel
        {
            AutoSize = true,
            FlowDirection = FlowDirection.RightToLeft,
            Dock = DockStyle.Fill,
        };
        buttonRow.Controls.Add(patchButton);
        layout.Controls.Add(buttonRow, 0, 3);
        layout.SetColumnSpan(buttonRow, 3);

        layout.Controls.Add(logBox, 0, 4);
        layout.SetColumnSpan(logBox, 3);

        browseButton.Click += (_, _) =>
        {
            using var dialog = new OpenFileDialog
            {
                Filter = "NosTale client (*.exe)|*.exe|All files (*.*)|*.*",
                Title = "Select NosCore.exe",
            };
            if (dialog.ShowDialog(this) == DialogResult.OK)
            {
                exeBox.Text = dialog.FileName;
                outputNameBox.Text =
                    Path.GetFileNameWithoutExtension(dialog.FileName) + "_patched" + Path.GetExtension(dialog.FileName);
            }
        };

        patchButton.Click += (_, _) =>
        {
            logBox.Clear();
            RunPatch(newAddressBox.Text.Trim(), exeBox.Text.Trim(), outputNameBox.Text.Trim(), logBox);
        };

        page.Controls.Add(layout);
        return page;
    }

    private static void RunPatch(string newAddress, string exePath, string outputName, TextBox logBox)
    {
        void Log(string msg) => logBox.AppendText(msg + Environment.NewLine);

        if (string.IsNullOrWhiteSpace(exePath) || !File.Exists(exePath))
        {
            Log("Pick a NosCore.exe first.");
            return;
        }
        if (string.IsNullOrWhiteSpace(newAddress))
        {
            Log("Enter a new address first.");
            return;
        }
        if (string.IsNullOrWhiteSpace(outputName))
        {
            Log("Output filename is empty.");
            return;
        }

        byte[] bytes;
        try
        {
            bytes = File.ReadAllBytes(exePath);
        }
        catch (Exception ex)
        {
            Log($"Read failed: {ex.Message}");
            return;
        }

        var ipResult = ClientPatcher.PatchServerAddress(bytes, newAddress);
        Log(ipResult.Log);
        if (!ipResult.Success) return;

        var mcResult = ClientPatcher.PatchMultiClient(bytes);
        Log(mcResult.Log);
        // Multiclient failing is non-fatal — still write out the IP-patched binary.

        var outPath = Path.Combine(Path.GetDirectoryName(exePath) ?? ".", outputName);
        if (string.Equals(Path.GetFullPath(outPath), Path.GetFullPath(exePath), StringComparison.OrdinalIgnoreCase))
        {
            Log("Refusing to overwrite the source exe — change the output filename.");
            return;
        }

        try
        {
            File.WriteAllBytes(outPath, bytes);
        }
        catch (Exception ex)
        {
            Log($"Write failed: {ex.Message}");
            return;
        }

        Log($"Wrote {outPath}");
    }

    private TabPage BuildAboutTab()
    {
        var page = new TabPage("About");

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 3,
        };
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 50));

        var text = new Label
        {
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.BottomCenter,
            Text = "NosCore.PacketLogger\n\nA NosTale packet logger for NosCore.",
        };
        layout.Controls.Add(text, 0, 0);

        const string url = "https://github.com/NosCoreIO/NosCore.DeveloperTools";
        var link = new LinkLabel
        {
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.TopCenter,
            Text = url,
            AutoSize = false,
            Height = 20,
        };
        link.LinkClicked += (_, _) =>
        {
            try
            {
                Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                _statusLabel.Text = $"Open link failed: {ex.Message}";
            }
        };
        layout.Controls.Add(link, 0, 1);

        page.Controls.Add(layout);
        return page;
    }

    private void WireEvents()
    {
        _log.PacketLogged += (_, packet) => BeginInvoke(() => AppendLog(packet));
        _log.Cleared += (_, _) => BeginInvoke(() => _logListBox.Items.Clear());

        _injection.PacketCaptured += (_, args) =>
        {
            // Drop filtered packets at intake so they never reach the log at all.
            if (!ShouldCapture(args.Packet)) return;
            _log.Add(args.Packet);
        };
        _injection.StatusChanged += (_, msg) => BeginInvoke(() => _statusLabel.Text = msg);

        FormClosing += (_, _) =>
        {
            _settings.MainWindow.Width = Size.Width;
            _settings.MainWindow.Height = Size.Height;
            _settings.MainWindow.X = Location.X;
            _settings.MainWindow.Y = Location.Y;
            Persist();
        };
    }

    private void AppendLog(LoggedPacket packet)
    {
        _logListBox.Items.Add(packet);
        if (_logListBox.Items.Count > 5000)
        {
            _logListBox.Items.RemoveAt(0);
        }
        _logListBox.TopIndex = Math.Max(0, _logListBox.Items.Count - 1);
    }

    private ContextMenuStrip BuildLogContextMenu()
    {
        var menu = new ContextMenuStrip();

        var copy = new ToolStripMenuItem("Copy") { ShortcutKeyDisplayString = "Ctrl+C" };
        copy.Click += (_, _) => CopySelected(withTags: false);
        menu.Items.Add(copy);

        var copyTags = new ToolStripMenuItem("Copy with tags");
        copyTags.Click += (_, _) => CopySelected(withTags: true);
        menu.Items.Add(copyTags);

        menu.Items.Add(new ToolStripSeparator());

        var selectAll = new ToolStripMenuItem("Select all") { ShortcutKeyDisplayString = "Ctrl+A" };
        selectAll.Click += (_, _) => SelectAllLog();
        menu.Items.Add(selectAll);

        return menu;
    }

    private void OnLogKeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Control && e.KeyCode == Keys.A)
        {
            SelectAllLog();
            e.SuppressKeyPress = true;
            e.Handled = true;
        }
        else if (e.Control && e.KeyCode == Keys.C)
        {
            CopySelected(withTags: false);
            e.SuppressKeyPress = true;
            e.Handled = true;
        }
    }

    private void SelectAllLog()
    {
        for (var i = 0; i < _logListBox.Items.Count; i++)
        {
            _logListBox.SetSelected(i, true);
        }
    }

    private void CopySelected(bool withTags)
    {
        if (_logListBox.SelectedItems.Count == 0) return;
        var lines = _logListBox.SelectedItems
            .Cast<LoggedPacket>()
            .Select(p => withTags ? p.ToString() : p.Raw);
        var text = string.Join(Environment.NewLine, lines);
        if (!string.IsNullOrEmpty(text))
        {
            try { Clipboard.SetText(text); }
            catch { /* rare race with another clipboard owner — ignore */ }
        }
    }

    private async void SelectProcess()
    {
        using var dialog = new ProcessSelectorForm(_processService, _settings.ProcessFilterText, _settings.LastProcessName);
        if (dialog.ShowDialog(this) != DialogResult.OK || dialog.SelectedProcess is null)
        {
            _settings.ProcessFilterText = dialog.CurrentFilter;
            Persist();
            return;
        }

        _settings.ProcessFilterText = dialog.CurrentFilter;
        _settings.LastProcessName = dialog.SelectedProcess.Name;
        Persist();

        try
        {
            await _injection.AttachAsync(dialog.SelectedProcess.Id);
            Text = $"NosCore.PacketLogger — {dialog.SelectedProcess.Name} (pid {dialog.SelectedProcess.Id})";
        }
        catch (Exception ex)
        {
            _statusLabel.Text = $"Attach failed: {ex.Message}";
        }
    }

    private void Persist()
    {
        try
        {
            _settingsService.Save(_settings);
        }
        catch (Exception ex)
        {
            _statusLabel.Text = $"Settings save failed: {ex.Message}";
        }
    }
}
