using System.Collections.Concurrent;
using System.Diagnostics;
using NosCore.DeveloperTools.Models;
using NosCore.DeveloperTools.Remote;
using NosCore.DeveloperTools.Services;
using NosCore.Shared.Enumerations;

namespace NosCore.DeveloperTools.Forms;

public sealed class MainForm : Form
{
    private readonly SettingsService _settingsService;
    private readonly ProcessService _processService;
    private readonly IInjectionService _injection;
    private readonly PacketLogService _log;
    private readonly PacketValidationService _validation;
    private AppSettings _settings;

    private readonly ToolStripStatusLabel _statusLabel = new() { Text = "No process attached." };
    private readonly ListBox _logListBox = new();
    private readonly ListBox _issuesListBox = new();
    private readonly TextBox _failedHeadersBox = new()
    {
        Dock = DockStyle.Top,
        ReadOnly = true,
        Multiline = false,
        PlaceholderText = "Packet headers that have failed validation (cleared with the log).",
    };
    private readonly SortedSet<string> _failedHeaders = new(StringComparer.Ordinal);
    // High packet rates mean per-packet BeginInvoke + ListBox.Add would saturate the UI thread.
    // Capture threads enqueue here; a UI-thread timer drains the queue in one BeginUpdate/EndUpdate batch.
    private readonly ConcurrentQueue<LoggedPacket> _pendingPackets = new();
    private readonly ConcurrentQueue<PacketValidationIssue> _pendingIssues = new();
    private readonly System.Windows.Forms.Timer _flushTimer = new() { Interval = 50 };
    private const int LogCap = 5000;
    private const int IssuesCap = 5000;
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
        PacketLogService log,
        PacketValidationService validation)
    {
        _settingsService = settingsService;
        _processService = processService;
        _injection = injection;
        _log = log;
        _validation = validation;
        _settings = _settingsService.Load();

        Text = "NosCore.DeveloperTools";
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
                .GetManifestResourceStream("NosCore.DeveloperTools.logger.ico");
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
        tabs.TabPages.Add(BuildNosMallTab());
        tabs.TabPages.Add(BuildAuthTab());
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
        _logListBox.DrawMode = DrawMode.OwnerDrawFixed;
        _logListBox.ItemHeight = _logListBox.Font.Height + 2;
        // OwnerDraw disables ListBox's auto-measuring of item width, so pick a large
        // static extent covering anything we realistically capture (raw packets rarely
        // exceed ~500 chars × ~7 px/char).
        _logListBox.HorizontalExtent = 4000;
        _logListBox.DrawItem += LogListBox_DrawItem;
        _logListBox.KeyDown += OnListKeyDown;
        _logListBox.ContextMenuStrip = BuildListContextMenu(_logListBox);

        _issuesListBox.Dock = DockStyle.Fill;
        _issuesListBox.IntegralHeight = false;
        _issuesListBox.Font = new Font(FontFamily.GenericMonospace, 9F);
        _issuesListBox.HorizontalScrollbar = true;
        _issuesListBox.SelectionMode = SelectionMode.MultiExtended;
        _issuesListBox.KeyDown += OnListKeyDown;
        _issuesListBox.ContextMenuStrip = BuildListContextMenu(_issuesListBox, includeRawCopy: false);

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

        var subTabs = new TabControl { Dock = DockStyle.Fill };
        var logPage = new TabPage("Log");
        logPage.Controls.Add(_logListBox);
        var issuesPage = new TabPage("Issues");
        // Fill must be added before the docked Top control so it occupies the remaining space.
        issuesPage.Controls.Add(_issuesListBox);
        issuesPage.Controls.Add(_failedHeadersBox);
        subTabs.TabPages.Add(logPage);
        subTabs.TabPages.Add(issuesPage);

        page.Controls.Add(subTabs);
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


    private TabPage BuildNosMallTab()
    {
        var page = new TabPage("NosMall");

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 3,
            RowCount = 4,
            Padding = new Padding(10),
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        for (var i = 0; i < 4; i++) layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        var nm = _settings.NosMall;
        var sourceBox = new TextBox { Dock = DockStyle.Fill, ReadOnly = true, Text = nm.SourceDir };
        var urlBox = new TextBox { Dock = DockStyle.Fill, Text = nm.NewUrl };
        var browseSource = new Button { Text = "Browse…", AutoSize = true };
        var patchButton = new Button { Text = "Patch all", AutoSize = true };
        var liveUrlBox = new TextBox
        {
            Dock = DockStyle.Fill, ReadOnly = true,
            PlaceholderText = "Auto-fills when you open NosMall in-game (requires Hook DLL injected)",
        };
        var logBox = new TextBox
        {
            Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical,
            Dock = DockStyle.Fill, Font = new Font(FontFamily.GenericMonospace, 9F), Height = 220,
        };

        layout.Controls.Add(new Label { Text = "NostaleData dir:", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 0);
        layout.Controls.Add(sourceBox, 1, 0);
        layout.Controls.Add(browseSource, 2, 0);
        layout.Controls.Add(new Label { Text = "New base URL:", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 1);
        layout.Controls.Add(urlBox, 1, 1);
        layout.SetColumnSpan(urlBox, 2);

        var btnRow = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Dock = DockStyle.Fill };
        btnRow.Controls.Add(patchButton);
        layout.Controls.Add(btnRow, 0, 2);
        layout.SetColumnSpan(btnRow, 3);

        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.Controls.Add(new Label { Text = "Live URL:", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 3);
        layout.Controls.Add(liveUrlBox, 1, 3);
        layout.SetColumnSpan(liveUrlBox, 2);
        layout.RowCount += 1;
        layout.Controls.Add(logBox, 0, 4);
        layout.SetColumnSpan(logBox, 3);

        void PersistNm()
        {
            _settings.NosMall.SourceDir = sourceBox.Text;
            _settings.NosMall.NewUrl = urlBox.Text;
            Persist();
        }

        browseSource.Click += (_, _) =>
        {
            using var dialog = new FolderBrowserDialog
            {
                Description = "Pick the NostaleData folder containing NScliData_*.NOS",
                ShowNewFolderButton = false,
                UseDescriptionForTitle = true,
                SelectedPath = string.IsNullOrEmpty(sourceBox.Text) ? "" : sourceBox.Text,
            };
            if (dialog.ShowDialog(this) == DialogResult.OK)
            {
                sourceBox.Text = dialog.SelectedPath;
                PersistNm();
            }
        };
        urlBox.TextChanged += (_, _) => PersistNm();

        patchButton.Click += (_, _) =>
        {
            logBox.Clear();
            void Log(string msg) => logBox.AppendText(msg + Environment.NewLine);

            if (string.IsNullOrWhiteSpace(sourceBox.Text) || !Directory.Exists(sourceBox.Text))
            {
                Log("Pick the NostaleData folder first.");
                return;
            }
            if (string.IsNullOrWhiteSpace(urlBox.Text))
            {
                Log("Enter the replacement URL.");
                return;
            }

            var files = Directory.GetFiles(sourceBox.Text, "NScliData_*.NOS", SearchOption.TopDirectoryOnly);
            if (files.Length == 0)
            {
                Log($"No NScliData_*.NOS files found under {sourceBox.Text}.");
                return;
            }

            var url = urlBox.Text.Trim();
            var totalFiles = 0;
            foreach (var path in files)
            {
                var name = Path.GetFileName(path);
                Log($"--- {name} ---");
                byte[] bytes;
                try { bytes = File.ReadAllBytes(path); }
                catch (Exception ex) { Log($"  read failed: {ex.Message}"); continue; }

                var result = NosMallUrlPatcher.Patch(bytes, url);
                foreach (var line in result.Log.TrimEnd().Split(Environment.NewLine))
                {
                    Log("  " + line);
                }
                if (!result.Success || result.Output is null) continue;

                // Back up the pristine original on first patch; leave an
                // existing .old alone so repeated patches don't overwrite
                // the clean copy with an already-patched one.
                var backup = path + ".old";
                if (!File.Exists(backup))
                {
                    try { File.Copy(path, backup); Log($"  backup: {Path.GetFileName(backup)}"); }
                    catch (Exception ex) { Log($"  backup failed (aborting file): {ex.Message}"); continue; }
                }
                try { File.WriteAllBytes(path, result.Output); }
                catch (Exception ex) { Log($"  write failed: {ex.Message}"); continue; }
                Log($"  wrote {name} in place");
                totalFiles++;
            }
            Log("");
            Log($"Done. Patched {totalFiles}/{files.Length} archive(s). Original copies kept with .old suffix.");
        };

        _injection.NosMallUrlReceived += (_, url) => BeginInvoke(() => liveUrlBox.Text = url);

        page.Controls.Add(layout);
        return page;
    }

    private TabPage BuildClientCreatorTab()
    {
        var page = new TabPage("Client creator");

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 3,
            RowCount = 6,
            Padding = new Padding(10),
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        for (var i = 0; i < 6; i++) layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        var cc = _settings.ClientCreator;
        var newAddressBox = new TextBox { Dock = DockStyle.Fill, PlaceholderText = "e.g. 192.168.1.50", Text = cc.NewAddress };
        var exeBox = new TextBox { Dock = DockStyle.Fill, ReadOnly = true, Text = cc.ClientExePath };
        var outputNameBox = new TextBox { Dock = DockStyle.Fill, PlaceholderText = "(auto-filled once you pick an exe)", Text = cc.OutputName };
        var browseButton = new Button { Text = "Browse…", AutoSize = true };
        var patchButton = new Button { Text = "Patch", AutoSize = true };

        var modeOptions = new (EntryPatchMode Mode, string Label)[]
        {
            (EntryPatchMode.DefaultToEntwell, "Default to EntwellNostaleClient (gf still works, but exits with EOSError 1400)"),
            (EntryPatchMode.OnlyEntwell,      "Only EntwellNostaleClient (force Entwell always, gf no longer works, clean exit)"),
            (EntryPatchMode.None,             "No parameter patch (double-click does nothing; must pass argv manually)"),
        };
        var modeCombo = new ComboBox { Dock = DockStyle.Fill, DropDownStyle = ComboBoxStyle.DropDownList };
        foreach (var (_, label) in modeOptions) modeCombo.Items.Add(label);
        modeCombo.SelectedIndex = Array.FindIndex(modeOptions, o => o.Mode == cc.EntryPatchMode);
        if (modeCombo.SelectedIndex < 0) modeCombo.SelectedIndex = 0;
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

        layout.Controls.Add(new Label { Text = "Entry patch:", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 3);
        layout.Controls.Add(modeCombo, 1, 3);
        layout.SetColumnSpan(modeCombo, 2);

        var buttonRow = new FlowLayoutPanel
        {
            AutoSize = true,
            FlowDirection = FlowDirection.RightToLeft,
            Dock = DockStyle.Fill,
        };
        buttonRow.Controls.Add(patchButton);
        layout.Controls.Add(buttonRow, 0, 4);
        layout.SetColumnSpan(buttonRow, 3);

        layout.Controls.Add(logBox, 0, 5);
        layout.SetColumnSpan(logBox, 3);

        browseButton.Click += (_, _) =>
        {
            using var dialog = new OpenFileDialog
            {
                Filter = "NosTale client (*.exe)|*.exe|All files (*.*)|*.*",
                Title = "Select NostaleClientX.exe",
            };
            if (dialog.ShowDialog(this) == DialogResult.OK)
            {
                exeBox.Text = dialog.FileName;
                outputNameBox.Text =
                    Path.GetFileNameWithoutExtension(dialog.FileName) + "_patched" + Path.GetExtension(dialog.FileName);
            }
        };

        void PersistCreator()
        {
            _settings.ClientCreator.NewAddress = newAddressBox.Text;
            _settings.ClientCreator.ClientExePath = exeBox.Text;
            _settings.ClientCreator.OutputName = outputNameBox.Text;
            Persist();
        }

        newAddressBox.TextChanged += (_, _) => PersistCreator();
        exeBox.TextChanged += (_, _) => PersistCreator();
        outputNameBox.TextChanged += (_, _) => PersistCreator();
        modeCombo.SelectedIndexChanged += (_, _) =>
        {
            _settings.ClientCreator.EntryPatchMode = modeOptions[modeCombo.SelectedIndex].Mode;
            Persist();
        };

        patchButton.Click += (_, _) =>
        {
            logBox.Clear();
            var mode = modeOptions[modeCombo.SelectedIndex].Mode;
            RunPatch(newAddressBox.Text.Trim(), exeBox.Text.Trim(), outputNameBox.Text.Trim(), mode, logBox);
        };

        page.Controls.Add(layout);
        return page;
    }

    private static void RunPatch(string newAddress, string exePath, string outputName, EntryPatchMode mode, TextBox logBox)
    {
        void Log(string msg) => logBox.AppendText(msg + Environment.NewLine);

        if (string.IsNullOrWhiteSpace(exePath) || !File.Exists(exePath))
        {
            Log("Pick a NostaleClientX.exe first.");
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

        switch (mode)
        {
            case EntryPatchMode.DefaultToEntwell:
                Log(ClientPatcher.PatchAllowNoArg(bytes).Log);
                Log(ClientPatcher.PatchDefaultToEntwell(bytes).Log);
                break;
            case EntryPatchMode.OnlyEntwell:
                Log(ClientPatcher.PatchForceEntwell(bytes).Log);
                break;
            case EntryPatchMode.None:
                Log("No parameter patch: exe is unmodified on the entry path.");
                break;
        }

        var stubResult = ClientPatcher.PatchImportName(bytes);
        Log(stubResult.Log);

        var outDir = Path.GetDirectoryName(exePath) ?? ".";
        var outPath = Path.Combine(outDir, outputName);
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

        // Drop our gf_wrapper stub next to the patched exe. The import-name
        // rewrite above points the exe at 'noscore_gf.dll' so we don't
        // clobber the original.
        if (stubResult.Success)
        {
            var stubPath = Path.Combine(outDir, "noscore_gf.dll");
            try
            {
                using var stubStream = typeof(MainForm).Assembly.GetManifestResourceStream("noscore_gf.dll")
                    ?? throw new FileNotFoundException("Stub DLL not embedded in this build.");
                using var outStream = File.Create(stubPath);
                stubStream.CopyTo(outStream);
                Log($"Wrote {stubPath}");
            }
            catch (Exception ex)
            {
                Log($"Stub DLL deploy failed: {ex.Message}");
            }
        }
    }

    private TabPage BuildAuthTab()
    {
        var page = new TabPage("Auth");

        var auth = _settings.Auth;
        var serverBox = new TextBox { Dock = DockStyle.Fill, Text = auth.ServerUrl };
        var userBox = new TextBox { Dock = DockStyle.Fill, PlaceholderText = "username", Text = auth.Username };
        var passBox = new TextBox { Dock = DockStyle.Fill, UseSystemPasswordChar = true, PlaceholderText = "password" };
        var mfaBox = new TextBox { Dock = DockStyle.Fill, PlaceholderText = "MFA code (optional)" };
        // RegionType's ordinal is the numeric "gf <N>" arg the NosTale client expects;
        // its name (EN, DE, FR…) is what NosCore's auth endpoint wants in `gfLang`.
        var regions = Enum.GetValues<RegionType>();
        var gfLangCombo = new ComboBox { Dock = DockStyle.Fill, DropDownStyle = ComboBoxStyle.DropDownList };
        foreach (var r in regions) gfLangCombo.Items.Add(r.ToString());
        var defaultIndex = Enum.TryParse<RegionType>(auth.GfLang, true, out var savedRegion) ? (int)savedRegion : 0;
        gfLangCombo.SelectedIndex = defaultIndex;
        var localeBox = new TextBox { Dock = DockStyle.Fill, Text = auth.Locale };
        var clientExeBox = new TextBox { Dock = DockStyle.Fill, ReadOnly = true, Text = auth.ClientExePath };
        var browseClientBtn = new Button { Text = "Browse…", AutoSize = true };
        var skipLaunchBox = new CheckBox { Text = "Skip client launch (for manual debug)", AutoSize = true };
        var primaryBtn = new Button { Text = "Sign in && launch", AutoSize = true };
        var httpLog = new TextBox
        {
            Multiline = true, ReadOnly = true, Dock = DockStyle.Fill,
            ScrollBars = ScrollBars.Vertical, Font = new Font(FontFamily.GenericMonospace, 9F),
        };
        var httpPanel = new GroupBox { Text = "HTTP (NosCore auth)", Dock = DockStyle.Fill, Padding = new Padding(4) };
        httpPanel.Controls.Add(httpLog);

        AuthResult? authResult = null;

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 4,
            Padding = new Padding(10),
        };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        root.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));

        void AddRow(Label leftLabel, Control leftField, Label? rightLabel, Control? rightField)
        {
            var rowIndex = root.RowCount;
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.Controls.Add(leftLabel, 0, rowIndex);
            root.Controls.Add(leftField, 1, rowIndex);
            if (rightLabel is not null && rightField is not null)
            {
                root.Controls.Add(rightLabel, 2, rowIndex);
                root.Controls.Add(rightField, 3, rowIndex);
            }
            else
            {
                root.SetColumnSpan(leftField, 3);
            }
            root.RowCount = rowIndex + 1;
        }

        Label L(string text) => new() { Text = text, AutoSize = true, Anchor = AnchorStyles.Left };

        AddRow(L("Server URL:"), serverBox, null, null);
        AddRow(L("Username:"), userBox, L("Password:"), passBox);
        AddRow(L("gfLang:"), gfLangCombo, L("locale:"), localeBox);
        AddRow(L("MFA:"), mfaBox, null, null);
        AddRow(L("Client exe:"), clientExeBox, L(""), browseClientBtn);

        var actionRow = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill };
        actionRow.Controls.Add(primaryBtn);
        actionRow.Controls.Add(skipLaunchBox);
        AddRow(L(""), actionRow, null, null);

        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.Controls.Add(httpPanel, 0, root.RowCount);
        root.SetColumnSpan(httpPanel, 4);
        root.RowCount++;

        void LogHttp(string line) => BeginInvoke(() =>
        {
            httpLog.AppendText($"[{DateTime.Now:HH:mm:ss.fff}] {line}{Environment.NewLine}");
        });

        void PersistAuth()
        {
            _settings.Auth.ServerUrl = serverBox.Text;
            _settings.Auth.Username = userBox.Text;
            _settings.Auth.GfLang = regions[gfLangCombo.SelectedIndex].ToString();
            _settings.Auth.Locale = localeBox.Text;
            _settings.Auth.ClientExePath = clientExeBox.Text;
            Persist();
        }

        serverBox.TextChanged += (_, _) => PersistAuth();
        userBox.TextChanged += (_, _) => PersistAuth();
        gfLangCombo.SelectedIndexChanged += (_, _) => PersistAuth();
        localeBox.TextChanged += (_, _) => PersistAuth();
        clientExeBox.TextChanged += (_, _) => PersistAuth();

        browseClientBtn.Click += (_, _) =>
        {
            using var dialog = new OpenFileDialog
            {
                Filter = "NosTale client (*.exe)|*.exe|All files (*.*)|*.*",
                Title = "Select NosTale client exe",
            };
            if (dialog.ShowDialog(this) == DialogResult.OK)
            {
                clientExeBox.Text = dialog.FileName;
            }
        };

        primaryBtn.Click += async (_, _) =>
        {
            primaryBtn.Enabled = false;
            try
            {
                if (string.IsNullOrWhiteSpace(serverBox.Text))
                {
                    LogHttp("Enter a server URL first.");
                    return;
                }
                if (string.IsNullOrWhiteSpace(clientExeBox.Text) || !File.Exists(clientExeBox.Text))
                {
                    LogHttp("Pick the NosTale client exe first.");
                    return;
                }

                using var client = new NosCoreAuthClient(serverBox.Text.Trim(), LogHttp);
                var mfa = string.IsNullOrWhiteSpace(mfaBox.Text) ? null : mfaBox.Text.Trim();
                var region = regions[gfLangCombo.SelectedIndex];
                authResult = await client.AuthenticateAsync(
                    userBox.Text.Trim(), passBox.Text, region.ToString(), localeBox.Text.Trim(), mfa,
                    CancellationToken.None);
                LogHttp($"Auth ok. account={authResult.PlatformGameAccountId} code={authResult.AuthCode}");

                if (skipLaunchBox.Checked)
                {
                    LogHttp("Skip-launch mode: env vars are below. Start the client yourself.");
                    LogHttp($"  _NC_AUTH_CODE={authResult.AuthCode}");
                    LogHttp($"  \"{clientExeBox.Text}\" gf {(int)region}");
                    LogHttp("In cmd.exe:");
                    LogHttp($"  set _NC_AUTH_CODE={authResult.AuthCode}");
                    LogHttp($"  \"C:\\path\\to\\x32dbg.exe\" \"{clientExeBox.Text}\" gf {(int)region}");
                    return;
                }

                var psi = new ProcessStartInfo
                {
                    FileName = clientExeBox.Text,
                    // Client parses the second token as an int — must be the numeric
                    // RegionType ordinal, not the code.
                    Arguments = $"gf {(int)region}",
                    WorkingDirectory = Path.GetDirectoryName(clientExeBox.Text) ?? Environment.CurrentDirectory,
                    UseShellExecute = false,
                };
                psi.EnvironmentVariables["_NC_AUTH_CODE"] = authResult.AuthCode;

                var proc = Process.Start(psi);
                LogHttp($"Started client pid={proc?.Id}");
            }
            catch (Exception ex)
            {
                LogHttp($"Failed: {ex.Message}");
            }
            finally
            {
                primaryBtn.Enabled = true;
            }
        };

        page.Controls.Add(root);
        return page;
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
            Text = "NosCore.DeveloperTools\n\nA set of developer tools for NosTale / NosCore.",
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
        _log.PacketLogged += (_, packet) => _pendingPackets.Enqueue(packet);
        _log.Cleared += (_, _) => BeginInvoke(() =>
        {
            while (_pendingPackets.TryDequeue(out _)) { }
            while (_pendingIssues.TryDequeue(out _)) { }
            _logListBox.Items.Clear();
            _issuesListBox.Items.Clear();
            _failedHeaders.Clear();
            _failedHeadersBox.Text = string.Empty;
        });

        _injection.PacketCaptured += (_, args) =>
        {
            // Drop filtered packets at intake so they never reach the log at all.
            if (!ShouldCapture(args.Packet)) return;
            // Stamp Issue before enqueueing so the Log flush sees the flag on first draw.
            var issue = _validation.Validate(args.Packet);
            if (issue is not null)
            {
                args.Packet.Issue = issue.Category;
                _pendingIssues.Enqueue(issue);
            }
            _log.Add(args.Packet);
        };
        _injection.StatusChanged += (_, msg) => BeginInvoke(() => _statusLabel.Text = msg);

        _flushTimer.Tick += (_, _) => FlushPendingPackets();
        _flushTimer.Start();

        FormClosing += (_, _) =>
        {
            _flushTimer.Stop();
            _settings.MainWindow.Width = Size.Width;
            _settings.MainWindow.Height = Size.Height;
            _settings.MainWindow.X = Location.X;
            _settings.MainWindow.Y = Location.Y;
            Persist();
        };
    }

    private void FlushPendingPackets()
    {
        FlushQueueInto(_pendingPackets, _logListBox, LogCap);
        FlushIssues();
    }

    private void FlushIssues()
    {
        if (_pendingIssues.IsEmpty) return;

        var buffer = new List<PacketValidationIssue>();
        while (_pendingIssues.TryDequeue(out var issue))
        {
            buffer.Add(issue);
        }
        if (buffer.Count == 0) return;

        var headersDirty = false;
        foreach (var issue in buffer)
        {
            var h = issue.Packet.Header;
            if (!string.IsNullOrEmpty(h) && _failedHeaders.Add(h))
            {
                headersDirty = true;
            }
        }

        _issuesListBox.BeginUpdate();
        try
        {
            _issuesListBox.Items.AddRange(buffer.Cast<object>().ToArray());
            var excess = _issuesListBox.Items.Count - IssuesCap;
            for (var i = 0; i < excess; i++)
            {
                _issuesListBox.Items.RemoveAt(0);
            }
            _issuesListBox.TopIndex = Math.Max(0, _issuesListBox.Items.Count - 1);
        }
        finally
        {
            _issuesListBox.EndUpdate();
        }

        if (headersDirty)
        {
            _failedHeadersBox.Text = string.Join(", ", _failedHeaders);
        }
    }

    private static void FlushQueueInto<T>(ConcurrentQueue<T> source, ListBox target, int cap)
    {
        if (source.IsEmpty) return;

        // Snapshot the queue to a local array so the batch add runs in a single
        // BeginUpdate/EndUpdate block even if more items arrive during the drain.
        var buffer = new List<T>();
        while (source.TryDequeue(out var item))
        {
            buffer.Add(item!);
        }
        if (buffer.Count == 0) return;

        target.BeginUpdate();
        try
        {
            target.Items.AddRange(buffer.Cast<object>().ToArray());
            var excess = target.Items.Count - cap;
            for (var i = 0; i < excess; i++)
            {
                target.Items.RemoveAt(0);
            }
            target.TopIndex = Math.Max(0, target.Items.Count - 1);
        }
        finally
        {
            target.EndUpdate();
        }
    }

    private ContextMenuStrip BuildListContextMenu(ListBox list, bool includeRawCopy = true)
    {
        var menu = new ContextMenuStrip();

        if (includeRawCopy)
        {
            var copy = new ToolStripMenuItem("Copy") { ShortcutKeyDisplayString = "Ctrl+C" };
            copy.Click += (_, _) => CopySelected(list, withTags: false);
            menu.Items.Add(copy);

            var copyTags = new ToolStripMenuItem("Copy with tags");
            copyTags.Click += (_, _) => CopySelected(list, withTags: true);
            menu.Items.Add(copyTags);
        }
        else
        {
            // For the Issues listbox, raw-only copy is useless — the tags carry the category + detail.
            var copyTags = new ToolStripMenuItem("Copy") { ShortcutKeyDisplayString = "Ctrl+C" };
            copyTags.Click += (_, _) => CopySelected(list, withTags: true);
            menu.Items.Add(copyTags);
        }

        menu.Items.Add(new ToolStripSeparator());

        var selectAll = new ToolStripMenuItem("Select all") { ShortcutKeyDisplayString = "Ctrl+A" };
        selectAll.Click += (_, _) => SelectAll(list);
        menu.Items.Add(selectAll);

        return menu;
    }

    private void OnListKeyDown(object? sender, KeyEventArgs e)
    {
        if (sender is not ListBox list) return;
        if (e.Control && e.KeyCode == Keys.A)
        {
            SelectAll(list);
            e.SuppressKeyPress = true;
            e.Handled = true;
        }
        else if (e.Control && e.KeyCode == Keys.C)
        {
            // Issues listbox: always copy with tags (the category + detail is the whole point).
            var withTags = list == _issuesListBox;
            CopySelected(list, withTags);
            e.SuppressKeyPress = true;
            e.Handled = true;
        }
    }

    private void LogListBox_DrawItem(object? sender, DrawItemEventArgs e)
    {
        if (e.Index < 0 || e.Index >= _logListBox.Items.Count) return;
        e.DrawBackground();

        const int stripeWidth = 4;
        var packet = _logListBox.Items[e.Index] as LoggedPacket;
        if (packet?.Issue is { } category)
        {
            var color = category switch
            {
                ValidationCategory.Missing => Color.Gold,
                ValidationCategory.WrongStructure => Color.IndianRed,
                ValidationCategory.WrongTag => Color.DarkOrange,
                _ => Color.Transparent,
            };
            using var brush = new SolidBrush(color);
            e.Graphics.FillRectangle(brush, e.Bounds.Left, e.Bounds.Top, stripeWidth, e.Bounds.Height);
        }

        var fg = (e.State & DrawItemState.Selected) != 0 ? SystemColors.HighlightText : SystemColors.WindowText;
        var textBounds = new Rectangle(
            e.Bounds.Left + stripeWidth + 2, e.Bounds.Top,
            e.Bounds.Width - stripeWidth - 2, e.Bounds.Height);
        TextRenderer.DrawText(
            e.Graphics,
            packet?.ToString() ?? _logListBox.Items[e.Index]?.ToString() ?? string.Empty,
            e.Font ?? _logListBox.Font,
            textBounds, fg,
            TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
        e.DrawFocusRectangle();
    }

    private static void SelectAll(ListBox list)
    {
        list.BeginUpdate();
        try
        {
            for (var i = 0; i < list.Items.Count; i++)
            {
                list.SetSelected(i, true);
            }
        }
        finally
        {
            list.EndUpdate();
        }
    }

    private static void CopySelected(ListBox list, bool withTags)
    {
        if (list.SelectedItems.Count == 0) return;
        var lines = list.SelectedItems.Cast<object>().Select(item => item switch
        {
            LoggedPacket p => withTags ? p.ToString() : p.Raw,
            PacketValidationIssue i => withTags ? i.ToString() : i.Packet.Raw,
            _ => item?.ToString() ?? string.Empty,
        });
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
            Text = $"NosCore.DeveloperTools — {dialog.SelectedProcess.Name} (pid {dialog.SelectedProcess.Id})";
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
