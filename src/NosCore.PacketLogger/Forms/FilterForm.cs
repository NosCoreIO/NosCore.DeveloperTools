using NosCore.PacketLogger.Models;

namespace NosCore.PacketLogger.Forms;

public sealed class FilterForm : Form
{
    private readonly PacketFilters _working;

    private readonly ListBox _sendList = new() { Dock = DockStyle.Fill };
    private readonly TextBox _sendInput = new() { Dock = DockStyle.Fill };
    private readonly ComboBox _sendMode = new() { Dock = DockStyle.Fill, DropDownStyle = ComboBoxStyle.DropDownList };

    private readonly ListBox _recvList = new() { Dock = DockStyle.Fill };
    private readonly TextBox _recvInput = new() { Dock = DockStyle.Fill };
    private readonly ComboBox _recvMode = new() { Dock = DockStyle.Fill, DropDownStyle = ComboBoxStyle.DropDownList };

    public FilterForm(PacketFilters current)
    {
        // Deep clone so a Cancel reverts cleanly.
        _working = new PacketFilters
        {
            CaptureSend = current.CaptureSend,
            CaptureReceive = current.CaptureReceive,
            SendFilter = new List<string>(current.SendFilter),
            ReceiveFilter = new List<string>(current.ReceiveFilter),
            SendFilterIsWhitelist = current.SendFilterIsWhitelist,
            ReceiveFilterIsWhitelist = current.ReceiveFilterIsWhitelist,
        };

        Text = "Packet filters";
        MinimumSize = new Size(500, 360);
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.Sizable;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = false;

        Controls.Add(BuildBody());
        Controls.Add(BuildButtons());
    }

    public PacketFilters Result => _working;

    private Control BuildBody()
    {
        var split = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 1,
            Padding = new Padding(8),
        };
        split.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        split.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));

        split.Controls.Add(BuildSide("Send", _sendList, _sendInput, _sendMode, _working.SendFilter,
            () => _working.SendFilterIsWhitelist,
            v => _working.SendFilterIsWhitelist = v), 0, 0);
        split.Controls.Add(BuildSide("Recv", _recvList, _recvInput, _recvMode, _working.ReceiveFilter,
            () => _working.ReceiveFilterIsWhitelist,
            v => _working.ReceiveFilterIsWhitelist = v), 1, 0);

        return split;
    }

    private static GroupBox BuildSide(
        string title,
        ListBox list,
        TextBox input,
        ComboBox mode,
        List<string> backing,
        Func<bool> getWhitelist,
        Action<bool> setWhitelist)
    {
        var group = new GroupBox { Text = title, Dock = DockStyle.Fill, Padding = new Padding(6) };

        var grid = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 3,
        };
        grid.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        grid.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        grid.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

        mode.Items.AddRange(new object[] { "Blacklist", "Whitelist" });
        mode.SelectedIndex = getWhitelist() ? 1 : 0;
        mode.SelectedIndexChanged += (_, _) => setWhitelist(mode.SelectedIndex == 1);
        grid.Controls.Add(mode, 0, 0);
        grid.SetColumnSpan(mode, 2);

        foreach (var entry in backing)
        {
            list.Items.Add(entry);
        }
        grid.Controls.Add(list, 0, 1);

        var removeButton = new Button { Text = "Remove", AutoSize = true };
        removeButton.Click += (_, _) =>
        {
            if (list.SelectedIndex < 0) return;
            backing.RemoveAt(list.SelectedIndex);
            list.Items.RemoveAt(list.SelectedIndex);
        };
        grid.Controls.Add(removeButton, 1, 1);

        var inputRow = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            Height = 26,
            Margin = new Padding(0, 4, 0, 0),
        };
        inputRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        inputRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        var addButton = new Button { Text = "Add", AutoSize = true };
        addButton.Click += (_, _) =>
        {
            var token = input.Text.Trim();
            if (string.IsNullOrEmpty(token)) return;
            if (backing.Contains(token)) return;
            backing.Add(token);
            list.Items.Add(token);
            input.Clear();
            input.Focus();
        };
        input.KeyDown += (_, e) =>
        {
            if (e.KeyCode == Keys.Enter)
            {
                addButton.PerformClick();
                e.SuppressKeyPress = true;
            }
        };
        inputRow.Controls.Add(input, 0, 0);
        inputRow.Controls.Add(addButton, 1, 0);
        grid.Controls.Add(inputRow, 0, 2);
        grid.SetColumnSpan(inputRow, 2);

        group.Controls.Add(grid);
        return group;
    }

    private Control BuildButtons()
    {
        var row = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            FlowDirection = FlowDirection.RightToLeft,
            AutoSize = true,
            Padding = new Padding(8),
        };
        var ok = new Button { Text = "OK", DialogResult = DialogResult.OK, AutoSize = true };
        var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, AutoSize = true };
        row.Controls.Add(ok);
        row.Controls.Add(cancel);
        AcceptButton = ok;
        CancelButton = cancel;
        return row;
    }
}
