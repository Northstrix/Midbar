using System;
using System.Drawing;
using System.Windows.Forms;

namespace LCDImageUploader
{
    class image
    {
        private Bitmap srcImage; // Original image
        private Bitmap lcdImage; // Modified image for LCD
        private PictureBox previewBox;
        private string lastErrorStr = "";
        private short angle;
        private int img_x;
        private int img_y;
        private float zoom;
        private int w; // LCD image width
        private int h; // LCD image height

        public image(int _w, int _h)
        {
            w = _w;
            h = _h;
            reset();
            lcdImage = new Bitmap(w, h);
        }

        // Get last error
        public string lastError()
        {
            return lastErrorStr;
        }

        // Load image
        public bool load(string file)
        {
            // Try to load image
            try
            {
                srcImage = new Bitmap(file);
            }
            catch (Exception ex)
            {
                lastErrorStr = ex.Message;
                return false;
            }

            reset();
            adjust();

            return true;
        }

        // Zoom
        public void doZoom(float amount)
        {
            float oldZoom = zoom;
            zoom += amount * zoom;

            if (oldZoom != zoom)
                adjust();
        }

        // Move
        public void move(int x, int y)
        {
            img_x = x;
            img_y = y;
            adjust();
        }

        // Rotate
        public void rotate(int mouseX)
        {
            angle = (short)(mouseX % 360);
            adjust();
        }

        // Reset image edit stuff
        private void reset()
        {
            angle = 0;
            img_x = w / 2;
            img_y = h / 2;
            zoom = 1F;
        }

        // Set what picture box to use for previewing
        public void setPreviewBox(PictureBox box)
        {
            previewBox = box;
        }

        // Get pixel colour and convert to 12 bit
        public short GetPixel12(int x, int y)
        {
            Color pixelData     = lcdImage.GetPixel(x, y);
            byte blue           = (byte)(pixelData.B >> 4);
            byte green          = (byte)(pixelData.G >> 4);
            byte red            = (byte)(pixelData.R >> 4);
            short colour        = (short)(red << 8 | green << 4 | blue);
            return colour;
        }

        // Get pixel colour and convert to 16 bit
        public short GetPixel16(int x, int y)
        {
            Color pixelData = lcdImage.GetPixel(x, y);
            byte blue       = (byte)(pixelData.B >> 3);
            byte green      = (byte)(pixelData.G >> 2);
            byte red        = (byte)(pixelData.R >> 3);
            short colour    = (short)(red << 11 | green << 5 | blue);
            return colour;
        }

        // Get pixel colour and convert to 18 bit
        public int GetPixel18(int x, int y)
        {
            Color pixelData     = lcdImage.GetPixel(x, y);
            byte blue           = (byte)pixelData.B;
            byte green          = (byte)pixelData.G;
            byte red            = (byte)pixelData.R;
            int colour          = (int)(red << 16 | green << 8 | blue);
            return colour;
        }

        public void adjust()
        {
            //srcImage.RotateFlip(RotateFlipType.RotateNoneFlipNone);

            if (srcImage == null)
                return;

            // Resize image to fit LCD while keeping aspect ratio
            int width = srcImage.Width;
            int height = srcImage.Height;
            double ratio = (double)width / (double)height;

            int targetWidth = lcdImage.Width;
            int targetHeight = lcdImage.Height;
            double targetRatio = (double)targetWidth / (double)targetHeight;

            if (ratio > targetRatio) // Wide
            {
                height = (targetWidth * height) / width;
                width = targetWidth;
            }
            else if (ratio < targetRatio) // Tall
            {
                width = (targetHeight * width) / height;
                height = targetHeight;
            }
            else // Same
            {
                width = targetWidth;
                height = targetHeight;
            }

            int x = (width / 2) * -1;
            int y = (height / 2) * -1;

            x += (int)((img_x - (targetWidth / 2)) / zoom);
            y += (int)((img_y - (targetHeight / 2)) / zoom);

            Graphics g = Graphics.FromImage(lcdImage);
            g.Clear(Color.Black);
            g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.HighQuality;
            g.InterpolationMode = System.Drawing.Drawing2D.InterpolationMode.HighQualityBicubic;
            g.TranslateTransform((targetWidth / 2), (targetHeight / 2));
            g.RotateTransform(angle);
            g.ScaleTransform(zoom, zoom);
            g.DrawImage(srcImage, x, y, width, height);

            // Set preview image
            if(previewBox != null)
                previewBox.Image = lcdImage;
        }
    }
}
