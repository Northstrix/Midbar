/*
Midbar
Distributed under the MIT License
© Copyright Maxim Bortnikov 2024
For more information please visit
https://sourceforge.net/projects/midbar/
https://github.com/Northstrix/Midbar
Required libraries:
https://github.com/zhouyangchao/AES
https://github.com/peterferrie/serpent
https://github.com/ddokkaebi/Blowfish
https://github.com/Northstrix/DES_and_3DES_Library_for_MCUs
https://github.com/ulwanski/sha512
https://github.com/adafruit/Adafruit-ST7735-Library
https://github.com/adafruit/Adafruit-GFX-Library
https://github.com/adafruit/Adafruit_BusIO
https://github.com/intrbiz/arduino-crypto
*/
using System;
using System.Windows.Forms;
using System.Drawing;
using System.Drawing.Imaging;
using System.Threading;
using System.IO;

namespace LCDImageUploader
{
    public partial class Form1 : Form
    {
        const int IMAGE_WIDTH   = 160;
        const int IMAGE_HEIGHT  = 128;
        const int SERIAL_BAUD   = 115200;
  
        private serial serialPort;
        private image lcdImage          = new image(IMAGE_WIDTH, IMAGE_HEIGHT);
        private bool uploading          = false;
        private bool editImage          = false;

        public Form1()
        {
            InitializeComponent();

            this.Icon           = System.Drawing.Icon.ExtractAssociatedIcon(System.Reflection.Assembly.GetExecutingAssembly().Location);
            this.Text           = "Image Uploader/Converter v" + System.Reflection.Assembly.GetExecutingAssembly().GetName().Version.ToString();
            this.AllowDrop      = true;
            this.DragEnter      += new DragEventHandler(Form1_DragEnter);
            this.DragDrop       += new DragEventHandler(Form1_DragDrop);
            this.FormClosing    += new FormClosingEventHandler(Form1_Closing);

            this.picPreview.MouseDown   += new MouseEventHandler(picPreview_MouseDown);
            this.picPreview.MouseUp     += new MouseEventHandler(picPreview_MouseUp);
            this.picPreview.MouseMove   += new MouseEventHandler(picPreview_MouseMove);
            this.picPreview.MouseEnter  += new EventHandler(picPreview_MouseEnter);
            this.picPreview.MouseLeave  += new EventHandler(picPreview_MouseLeave);
            this.picPreview.MouseWheel  += new MouseEventHandler(picPreview_MouseWheel);
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            serialPort = new serial();
            updatePorts();

            lcdImage.setPreviewBox(picPreview);
            // Set open file dialog filter to only show supported image formats
            openFileDialog1.Filter = "";
            ImageCodecInfo[] codecs = ImageCodecInfo.GetImageEncoders();
            String sep = String.Empty;
            String allExtensions = String.Empty;
            foreach(ImageCodecInfo c in codecs)
            {
                String codecName = c.CodecName.Substring(8).Replace("Codec", "Files").Trim();
                String extensions = c.FilenameExtension.ToLower();
                openFileDialog1.Filter = String.Format("{0}{1}{2} ({3})|{3}", openFileDialog1.Filter, sep, codecName, extensions);
                allExtensions += extensions + ";";
                sep = "|";
            }
            allExtensions = allExtensions.TrimEnd(';');
            openFileDialog1.Filter = String.Format("{0}|{1}|{2}", "Image files", allExtensions, openFileDialog1.Filter);
            openFileDialog1.Filter = String.Format("{0}{1}{2} ({3})|{3}", openFileDialog1.Filter, sep, "All Files", "*.*");
        }

        // Close form
        private void Form1_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            serialPort.close();
        }

        // Drag and drop
        void Form1_DragEnter(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
                e.Effect = DragDropEffects.Copy;
        }

        // Drag and drop
        void Form1_DragDrop(object sender, DragEventArgs e)
        {
            string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
            loadImage(files[0]);
        }

        // Mouse enter preview image (for mouse wheel)
        void picPreview_MouseEnter(object sender, EventArgs e)
        {
            picPreview.Focus();
            this.Cursor = Cursors.SizeAll;
        }

        // Mouse leave preview image (for mouse wheel)
        void picPreview_MouseLeave(object sender, EventArgs e)
        {
            lblPreview.Focus();
            this.Cursor = Cursors.Default;
        }

        // Mouse wheel change preview image
        void picPreview_MouseWheel(object sender, MouseEventArgs e)
        {
            if (!uploading)
            {
                float amount = 0;
                if (e.Delta > 0)
                    amount = 0.1F;
                else if (e.Delta < 0)
                    amount = -0.1F;
                lcdImage.doZoom(amount);
            }
        }

        // Mouse down on preview image (for mouse move)
        void picPreview_MouseDown(object sender, MouseEventArgs e)
        {
            editImage = true;
        }

        // Mouse up on preview image (for mouse move)
        void picPreview_MouseUp(object sender, MouseEventArgs e)
        {
            editImage = false;
        }

        // Mouse move on preview image
        void picPreview_MouseMove(object sender, MouseEventArgs e)
        {
            if (editImage && !uploading)
            {
                if (e.Button == MouseButtons.Left)
                {
                    Point mousePos = Cursor.Position;
                    Point picPos = picPreview.PointToScreen(Point.Empty);
                    lcdImage.move(mousePos.X - picPos.X, mousePos.Y - picPos.Y);
                }
                else if (e.Button == MouseButtons.Right)
                    lcdImage.rotate(e.X);
            }
        }

        // Refresh ports button
        private void btnRefreshPorts_Click(object sender, EventArgs e)
        {
            updatePorts();
        }

        // Open image button
        private void btnOpenImg_Click(object sender, EventArgs e)
        {
            openFileDialog1.ShowDialog();
        }

        // Upload button
        private void btnUpload_Click(object sender, EventArgs e)
        {
            uploadImage();
        }

        // Fill drop down list with available ports
        private void updatePorts()
        {
            // Get ports
            string[] ports = serialPort.getPorts();

            // Clear list
            cbPorts.Items.Clear();
            cbPorts.Text = "";

            // Add ports to list
            foreach (string port in ports)
                cbPorts.Items.Add(port);

            // If a port is available then select it
            if (cbPorts.Items.Count > 0)
                cbPorts.SelectedIndex = 0;
        }

        // Open selected port
        private bool openPort(ref string errorStr)
        {
            // No ports listed
            if (cbPorts.Items.Count <= 0)
            {
                errorStr = "No ports available";
                return false;
            }

            // Get selected text
            string port = cbPorts.SelectedItem.ToString();
            if (port.Length < 4) // must be COM###
            {
                errorStr = "Invalid port";
                return false;
            }

            // Try to open port
            if (!serialPort.open(port, SERIAL_BAUD))
            {
                errorStr = serialPort.lastError();
                return false;
            }

            return true;
        }

        // Image selected from open file dialog
        private void openFileDialog1_FileOk(object sender, System.ComponentModel.CancelEventArgs e)
        {
            loadImage(openFileDialog1.FileName);
        }
        
        // Load image
        private void loadImage(string file)
        {
            if(!uploading)
            {
                if (!lcdImage.load(file))
                    MessageBox.Show("Error opening image: " + lcdImage.lastError(), "Image error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
        
        // Try opening port then upload data
        private void uploadImage()
        {
            if (!uploading)
            {
                // Try opening port
                string errorStr = "";
                if (!openPort(ref errorStr))
                {
                    serialPort.close();
                    MessageBox.Show(errorStr, "Serial error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                // Begin uploading
                MethodInvoker mi = new MethodInvoker(uploadImageInvoke);
                mi.BeginInvoke(null, null);
            }
        }
        private void updateProgressBar(int val)
        {
            pbUpload.Value = val;

            // Set custom color scheme
            pbUpload.Invoke(new Action(() =>
            {
                pbUpload.ForeColor = Color.FromArgb(0, 131, 235);
                pbUpload.BackColor = Color.FromArgb(238, 238, 238);
            }));
        }

        private void uploadImageInvoke()
        {
            if (picPreview.Image == null)
            {
                MessageBox.Show("No image loaded in the PictureBox.");
                return;
            }

            Bitmap bitmap = new Bitmap(picPreview.Image);

            try
            {
                using (FolderBrowserDialog folderBrowser = new FolderBrowserDialog())
                {
                    TransmitImageData((Bitmap)picPreview.Image);
                    serialPort.close();
                }
            }
            catch (IOException ex)
            {
                MessageBox.Show($"An error occurred: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void TransmitImageData(Bitmap bitmap)
        {
            int width = bitmap.Width;
            int height = bitmap.Height;

            int totalPixels = width * height;
            int pixelsSent = 0;
            // Transmit pixel data to Arduino
            for (int y = 0; y < height; y++)
            {
                for (int x = 0; x < width; x++)
                {
                    Color pixelColor = bitmap.GetPixel(x, y);

                    // Extract RGB components
                    byte r = pixelColor.R;
                    byte g = pixelColor.G;
                    byte b = pixelColor.B;

                    // Transmit pixel data to Arduino
                    TransmitByte(r);
                    TransmitByte(g);
                    TransmitByte(b);

                    pixelsSent++;

                    // Update progress bar
                    int progressPercentage = (int)((float)pixelsSent / totalPixels * 100);
                    pbUpload.Invoke(new Action(() => pbUpload.Value = progressPercentage));
                }
            }
            pbUpload.Invoke(new Action(() => pbUpload.Value = 0));
            MessageBox.Show("Done", "Transmission Complete!", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void TransmitByte(byte value)
        {
            serialPort.send(new byte[] { value }, 1);
        }

        // Function to convert a Color to a 16-bit value
        private ushort ConvertColorTo16Bit(Color color)
        {
            // Assuming 5 bits for red, 6 bits for green, and 5 bits for blue
            ushort red = (ushort)(color.R >> 3);
            ushort green = (ushort)(color.G >> 2);
            ushort blue = (ushort)(color.B >> 3);

            // Combine the bits to form a 16-bit color value
            ushort result = (ushort)((red << 11) | (green << 5) | blue);

            return result;
        }

        // Update progress bar
        private delegate void progressDelegate(int val);

        private void convert_button_Click(object sender, EventArgs e)
        {
            if (picPreview.Image == null)
            {
                MessageBox.Show("No image loaded in the PictureBox.");
                return;
            }

            Bitmap bitmap = new Bitmap(picPreview.Image);

            try
            {
                string folderPath = string.Empty;

                // Invoke dialog on the UI thread
                this.Invoke(new Action(() =>
                {
                    using (FolderBrowserDialog folderBrowser = new FolderBrowserDialog())
                    {
                        // Show the FolderBrowserDialog.
                        DialogResult result = folderBrowser.ShowDialog();

                        if (result == DialogResult.OK && !string.IsNullOrWhiteSpace(folderBrowser.SelectedPath))
                        {
                            folderPath = folderBrowser.SelectedPath;
                        }
                    }
                }));

                if (!string.IsNullOrEmpty(folderPath))
                {
                    using (StreamWriter redWriter = new StreamWriter(Path.Combine(folderPath, "red.txt")))
                    using (StreamWriter greenWriter = new StreamWriter(Path.Combine(folderPath, "green.txt")))
                    using (StreamWriter blueWriter = new StreamWriter(Path.Combine(folderPath, "blue.txt")))
                    using (StreamWriter color565Writer = new StreamWriter(Path.Combine(folderPath, "565_color.txt")))
                    using (StreamWriter blackAndWhiteWriter = new StreamWriter(Path.Combine(folderPath, "black_and_white.txt")))
                    {
                        int height = bitmap.Height;
                        int width = bitmap.Width;

                        redWriter.WriteLine($"const uint8_t red_col PROGMEM [{width}][{height}] = {{");
                        greenWriter.WriteLine($"const uint8_t green_col PROGMEM [{width}][{height}] = {{");
                        blueWriter.WriteLine($"const uint8_t blue_col PROGMEM [{width}][{height}] = {{");
                        color565Writer.WriteLine($"const uint16_t conv_to_565_img PROGMEM [{width}][{height}] = {{");
                        blackAndWhiteWriter.WriteLine($"const uint8_t black_and_white PROGMEM [{width}][{height}] = {{");

                        for (int x = 0; x < width; x++)
                        {
                            redWriter.Write("{");
                            greenWriter.Write("{");
                            blueWriter.Write("{");
                            color565Writer.Write("{");
                            blackAndWhiteWriter.Write("{");

                            for (int y = 0; y < height; y++)
                            {
                                Color pixelColor = bitmap.GetPixel(x, y);

                                // Extract 16-bit color
                                ushort color16bit = ConvertColorTo16Bit(pixelColor);

                                // Extract RGB components
                                int r = pixelColor.R;
                                int g = pixelColor.G;
                                int b = pixelColor.B;

                                // Convert to black and white
                                int bw = (int)(r * 0.3) + (int)(g * 0.59) + (int)(b * 0.11);

                                redWriter.Write($"{r}");
                                greenWriter.Write($"{g}");
                                blueWriter.Write($"{b}");
                                color565Writer.Write($"{color16bit}");
                                blackAndWhiteWriter.Write($"{bw}");

                                if (y < height - 1)
                                {
                                    redWriter.Write(",");
                                    greenWriter.Write(",");
                                    blueWriter.Write(",");
                                    color565Writer.Write(",");
                                    blackAndWhiteWriter.Write(",");
                                }
                            }

                            redWriter.WriteLine("},");
                            greenWriter.WriteLine("},");
                            blueWriter.WriteLine("},");
                            color565Writer.WriteLine("},");
                            blackAndWhiteWriter.WriteLine("},");

                        }

                        redWriter.WriteLine("};");
                        greenWriter.WriteLine("};");
                        blueWriter.WriteLine("};");
                        color565Writer.WriteLine("};");
                        blackAndWhiteWriter.WriteLine("};");
                    }
                }
                MessageBox.Show("Image Converted successfully!", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (IOException ex)
            {
                MessageBox.Show($"An error occurred: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            if (picPreview.Image == null)
            {
                MessageBox.Show("No image loaded in the PictureBox.");
                return;
            }
        }
    }
}
