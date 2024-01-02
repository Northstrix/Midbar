using System;
using System.Text;
using System.IO.Ports;
using System.Windows.Forms;
using System.Threading;

namespace LCDImageUploader
{
    class serial
    {
        SerialPort _serialPort;
        bool portOpen = false;
        string lastErrorStr = "";

        // Get last error
        public string lastError()
        {
            return lastErrorStr;
        }

        // Get list of ports
        public string[] getPorts()
        {
            return SerialPort.GetPortNames();
        }

        // Open port
        public bool open(string port, int baud)
        {
            if (portOpen)
                return true;
            _serialPort                 = new SerialPort(port, baud, Parity.None, 8, StopBits.One);
            _serialPort.ReadTimeout     = 500;
            _serialPort.WriteTimeout    = 500;
            _serialPort.WriteBufferSize = 16;
            _serialPort.ReadBufferSize  = 16;

            try
            {
                _serialPort.Open();
                portOpen = true;
            }
            catch (Exception e)
            {
                lastErrorStr = e.Message;
                return false;
            }

            return true;
        }

        // Close port
        public void close()
        {
            if (portOpen)
            {
                try
                {
                    _serialPort.Close();
                }
                catch (Exception e)
                {
                    lastErrorStr = e.Message;
                }
            }
            portOpen = false;
        }

        // Send data
        public bool send(byte[] data, int len)
        {
            try
            {
                if(!portOpen)
                {
                    lastErrorStr = "Port not open";
                    return false;
                }
                _serialPort.Write(data, 0, 1);
            }
            catch (Exception e)
            {
                lastErrorStr = e.Message;
                return false;
            }

            return true;
        }
    }
}
