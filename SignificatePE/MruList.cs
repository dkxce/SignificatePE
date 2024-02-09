using System;
using System.Collections.Generic;
using System.Windows.Forms;
using System.IO;
using System.Drawing;

namespace dkxce
{
    public class MruList
    {
        private static ToolStripRenderer menuRenderer = null;

        private string MRUListSavedFileName;
        private int MRUFilesCount;
        private List<FileInfo> MRUFilesInfos;
        private ToolStripMenuItem MyMenu;

        private bool UseSeparator = false;
        private ToolStripSeparator Separator = null;
        private ToolStripMenuItem[] MenuItems;

        // Raised when the user selects a file from the MRU list.
        public delegate void FileSelectedEventHandler(string file_name);
        public event FileSelectedEventHandler FileSelected;

        public int Count { get { return MRUFilesInfos.Count; } }       

        // Constructor.
        public MruList(string MRUFileName, ToolStripMenuItem menu, int num_files, System.Drawing.Image icon = null)
        {
            if(menuRenderer == null) ToolStripManager.Renderer = menuRenderer = new MruItemRenderer(menu);

            this.MRUListSavedFileName = MRUFileName;
            MyMenu = menu;
            MRUFilesCount = num_files;
            MRUFilesInfos = new List<FileInfo>();

            // Make a separator
            Separator = new ToolStripSeparator();
            Separator.Visible = false;
            if (UseSeparator) MyMenu.DropDownItems.Add(Separator);

            // Make the menu items we may later need.
            MenuItems = new ToolStripMenuItem[MRUFilesCount + 1];
            for (int i = 0; i < MRUFilesCount; i++)
            {
                MenuItems[i] = new ToolStripMenuItem();
                MenuItems[i].Visible = false;
                MenuItems[i].Image = icon;                
                MyMenu.DropDownItems.Add(MenuItems[i]);
            };
            
            // Reload items from the registry.
            LoadFiles();

            // Display the items.
            ShowFiles();
        }

        private void LoadFiles()
        {
            string filemru = this.MRUListSavedFileName;
            if (!File.Exists(filemru)) return; 

            FileStream fs = new FileStream(filemru, FileMode.Open, FileAccess.Read);
            StreamReader sr = new StreamReader(fs, System.Text.Encoding.GetEncoding(1251));
            while (!sr.EndOfStream)
            {
                string filename = sr.ReadLine();
                if (File.Exists(filename))
                    MRUFilesInfos.Add(new FileInfo(filename));
                else if (Directory.Exists(filename))
                        MRUFilesInfos.Add(new FileInfo(filename));
                        
            };
            sr.Close();
            fs.Close();
        }

        // Save the current items in the Registry.
        private void SaveFiles()
        {            
            string filemru = this.MRUListSavedFileName;
            if (filemru == null) return;
            FileStream fs = new FileStream(filemru, FileMode.Create, FileAccess.Write);
            StreamWriter sw = new StreamWriter(fs, System.Text.Encoding.GetEncoding(1251));
            foreach (FileInfo file_info in MRUFilesInfos)
                sw.WriteLine(file_info.FullName);
            sw.Close();
            fs.Close();            
        }

        // Remove a file's info from the list.
        private void RemoveFileInfo(string file_name)
        {
            // Remove occurrences of the file's information from the list.
            for (int i = MRUFilesInfos.Count - 1; i >= 0; i--)
            {
                if (MRUFilesInfos[i].FullName == file_name) MRUFilesInfos.RemoveAt(i);
            }
        }

        // Add a file to the list, rearranging if necessary.
        public void AddFile(string file_name)
        {
            // Remove the file from the list.
            RemoveFileInfo(file_name);

            // Add the file to the beginning of the list.
            MRUFilesInfos.Insert(0, new FileInfo(file_name));

            // If we have too many items, remove the last one.
            if (MRUFilesInfos.Count > MRUFilesCount) MRUFilesInfos.RemoveAt(MRUFilesCount);

            // Display the files.
            ShowFiles();

            // Update the Registry.
            SaveFiles();
        }

        // Remove a file from the list, rearranging if necessary.
        public void RemoveFile(string file_name)
        {
            // Remove the file from the list.
            RemoveFileInfo(file_name);

            // Display the files.
            ShowFiles();

            // Update the Registry.
            SaveFiles();
        }

        // Display the files in the menu items.
        private void ShowFiles()
        {
            Separator.Visible = (MRUFilesInfos.Count > 0);
            for (int i = 0; i < MRUFilesInfos.Count; i++)
            {
                string name = "`"+MRUFilesInfos[i].Name + "` at .. " + MRUFilesInfos[i].FullName.Remove(MRUFilesInfos[i].FullName.Length-MRUFilesInfos[i].Name.Length);
                while (name.Length > 90) name = name.Remove(name.IndexOf("` at .. ") + 8, 1);
                MenuItems[i].Text = string.Format("&{0} {1}", i + 1, name);
                MenuItems[i].Visible = true;
                MenuItems[i].Tag = MRUFilesInfos[i];
                MenuItems[i].Click -= File_Click;
                MenuItems[i].Click += File_Click;
            }
            for (int i = MRUFilesInfos.Count; i < MRUFilesCount; i++)
            {
                MenuItems[i].Visible = false;
                MenuItems[i].Click -= File_Click;
            }
        }

        // The user selected a file from the menu.
        private void File_Click(object sender, EventArgs e)
        {
            // Don't bother if no one wants to catch the event.
            if (FileSelected != null)
            {
                // Get the corresponding FileInfo object.
                ToolStripMenuItem menu_item = sender as ToolStripMenuItem;
                FileInfo file_info = menu_item.Tag as FileInfo;

                // Raise the event.
                FileSelected(file_info.FullName);
            }
        }        
    }

    /// <remarks>
    ///     ToolStripMenuItem.Tag must be FileInfo
    /// </remarks>
    public class MruItemRenderer : ToolStripProfessionalRenderer
    {
        private const int MaxPathLength = 40;
        private const int ItemOffset = 34;        

        public ToolStripMenuItem menu { set; get; } = null;
        
        public MruItemRenderer(ToolStripMenuItem menu = null) { this.menu = menu; }

        public static string TrimPathLength(string path, int maxL = MaxPathLength)
        {
            try
            {
                if (path.Length > maxL)
                {
                    string beg = "";
                    string end = "";
                    string[] ps = path.Split(new char[] { '\\' }, StringSplitOptions.RemoveEmptyEntries);
                    for (int i = 0; i < ps.Length; i++)
                    {
                        beg += beg.Length > 0 ? $"\\{ps[i]}" : ps[i];
                        end = (end.Length > 0 ? $"{ps[ps.Length - 1 - i]}\\" : ps[ps.Length - 1 - i]) + end;
                        if (beg.Length + end.Length < maxL) path = $"{beg} .. {end}"; else break;
                    };
                    return path;
                };
            }
            catch { };
            return path;
        }

        protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e)
        {
            ToolStripMenuItem mItem = e.Item as ToolStripMenuItem;
            
            if (mItem == null || this.menu == null) { base.OnRenderItemText(e); return; };
            if (mItem.OwnerItem != this.menu) { base.OnRenderItemText(e); return; };

            try
            {
                FileInfo fi = mItem.Tag as FileInfo;
                if (fi != null)
                {
                    string path = TrimPathLength(fi.FullName.Remove(fi.FullName.Length - fi.Name.Length));
                    // MRU
                    if (mItem.Text.StartsWith("&") && mItem.Text.Contains(" `") && int.TryParse(mItem.Text.Substring(1).Split(' ')[0], out int id))
                    {                        
                        int wi = ItemOffset;
                        {
                            // Num
                            e.Graphics.DrawString($"[{id}] ", e.TextFont, new SolidBrush(Color.Maroon), new Point(wi, 2));
                            wi += (int)e.Graphics.MeasureString($"[{id}] ", e.TextFont).Width;
                        };
                        {
                            // Name
                            Font f = new Font(e.TextFont, FontStyle.Bold);
                            e.Graphics.DrawString($"{fi.Name}", f, new SolidBrush(Color.Black), new Point(wi, 2));
                            wi += (int)e.Graphics.MeasureString($"{fi.Name}", f).Width;
                        };
                        {
                            // Dir
                            e.Graphics.DrawString($"{path}", e.TextFont, new SolidBrush(Color.Teal), new Point(wi, 2));
                        };
                        return;
                    };
                    // Not MRU
                    {
                        int wi = ItemOffset;                        
                        {
                            // Name
                            e.Graphics.DrawString($"{mItem.Text}", e.TextFont, new SolidBrush(Color.Black), new Point(wi, 2));
                            wi += (int)e.Graphics.MeasureString($"{mItem.Text}", e.TextFont).Width;
                        };
                        {
                            // Dir
                            e.Graphics.DrawString($"{path}", e.TextFont, new SolidBrush(Color.Teal), new Point(wi, 2));
                        };
                    };
                    return;
                };
            }
            catch { };            

            // default draw
            base.OnRenderItemText(e);
        }
    }
}
