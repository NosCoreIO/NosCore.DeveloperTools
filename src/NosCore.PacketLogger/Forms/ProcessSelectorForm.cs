using NosCore.PacketLogger.Services;

namespace NosCore.PacketLogger.Forms;

public sealed class ProcessSelectorForm : Form
{
    private readonly ProcessService _processService;
    private readonly TextBox _filterBox = new();
    private readonly ListBox _listBox = new();
    private readonly Button _refreshButton = new() { Text = "Refresh" };
    private readonly Button _okButton = new() { Text = "Select", DialogResult = DialogResult.OK };
    private readonly Button _cancelButton = new() { Text = "Cancel", DialogResult = DialogResult.Cancel };
    private string _preselectName;

    public ProcessSelectorForm(ProcessService processService, string initialFilter, string? preselectName)
    {
        _processService = processService;
        _preselectName = preselectName ?? string.Empty;

        Text = "Select process";
        StartPosition = FormStartPosition.CenterParent;
        ClientSize = new Size(420, 360);
        MinimumSize = new Size(360, 240);
        FormBorderStyle = FormBorderStyle.Sizable;
        MinimizeBox = false;
        MaximizeBox = false;

        var filterLabel = new Label
        {
            Text = "Filter:",
            AutoSize = true,
            Location = new Point(10, 13),
        };

        _filterBox.Location = new Point(60, 10);
        _filterBox.Width = ClientSize.Width - 70 - 80;
        _filterBox.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
        _filterBox.Text = initialFilter;
        _filterBox.TextChanged += (_, _) => Refresh();

        _refreshButton.Location = new Point(ClientSize.Width - 80, 8);
        _refreshButton.Width = 70;
        _refreshButton.Anchor = AnchorStyles.Top | AnchorStyles.Right;
        _refreshButton.Click += (_, _) => Refresh();

        _listBox.Location = new Point(10, 40);
        _listBox.Size = new Size(ClientSize.Width - 20, ClientSize.Height - 90);
        _listBox.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
        _listBox.DoubleClick += (_, _) =>
        {
            if (_listBox.SelectedItem is ProcessEntry)
            {
                DialogResult = DialogResult.OK;
                Close();
            }
        };

        _okButton.Location = new Point(ClientSize.Width - 170, ClientSize.Height - 35);
        _okButton.Width = 80;
        _okButton.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;

        _cancelButton.Location = new Point(ClientSize.Width - 85, ClientSize.Height - 35);
        _cancelButton.Width = 75;
        _cancelButton.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;

        Controls.AddRange(new Control[]
        {
            filterLabel,
            _filterBox,
            _refreshButton,
            _listBox,
            _okButton,
            _cancelButton,
        });

        AcceptButton = _okButton;
        CancelButton = _cancelButton;

        Load += (_, _) => Refresh();
    }

    public ProcessEntry? SelectedProcess => _listBox.SelectedItem as ProcessEntry;

    public string CurrentFilter => _filterBox.Text;

    public new void Refresh()
    {
        var entries = _processService.Enumerate(_filterBox.Text);
        _listBox.BeginUpdate();
        try
        {
            _listBox.Items.Clear();
            foreach (var entry in entries)
            {
                _listBox.Items.Add(entry);
            }

            if (!string.IsNullOrEmpty(_preselectName))
            {
                for (var i = 0; i < _listBox.Items.Count; i++)
                {
                    if (_listBox.Items[i] is ProcessEntry e
                        && string.Equals(e.Name, _preselectName, StringComparison.OrdinalIgnoreCase))
                    {
                        _listBox.SelectedIndex = i;
                        break;
                    }
                }
            }
        }
        finally
        {
            _listBox.EndUpdate();
        }
    }
}
