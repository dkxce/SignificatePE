using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Xml.Serialization;

namespace SignificatePE
{
    [Serializable]
    public class KeyValuePairSerializable<K, V>
    {
        public KeyValuePairSerializable() { }

        public KeyValuePairSerializable(KeyValuePair<K, V> pair)
        {
            Key = pair.Key;
            Value = pair.Value;
        }

        [XmlAttribute("key")]
        public K Key { get; set; }

        [XmlText]
        public V Value { get; set; }

        public override string ToString() => $"{Key}={Value}";
    }

    public class MakeCertConfig
    {
        [XmlIgnore]
        public Dictionary<string, string> CmdLineArguments { get; set; }  = new Dictionary<string, string>();

        [XmlIgnore]
        public Dictionary<string, string> SubjectCertificateName { get; set; } = new Dictionary<string, string>();

        [XmlIgnore]
        public Dictionary<string, string> OIDs { get; set; } = new Dictionary<string, string>();


        [XmlArray("Arguments")]
        [XmlArrayItem("arg")]
        [DebuggerBrowsable(DebuggerBrowsableState.Never)] // not necessary
        public KeyValuePairSerializable<string, string>[] ArgumentsXml
        {
            get
            {
                return CmdLineArguments?.Select(p => new KeyValuePairSerializable<string, string>(p)).ToArray();
            }
            set
            {
                CmdLineArguments = value?.ToDictionary(i => i.Key, i => i.Value);
            }
        }

        [XmlArray("SubjectCertificateName")]
        [XmlArrayItem("param")]
        [DebuggerBrowsable(DebuggerBrowsableState.Never)] // not necessary
        public KeyValuePairSerializable<string, string>[] SubjectCertificateNameXml
        {
            get
            {
                return SubjectCertificateName?.Select(p => new KeyValuePairSerializable<string, string>(p)).ToArray();
            }
            set
            {
                SubjectCertificateName = value?.ToDictionary(i => i.Key, i => i.Value);
            }
        }

        [XmlArray("OIDs")]
        [XmlArrayItem("oid")]
        [DebuggerBrowsable(DebuggerBrowsableState.Never)] // not necessary
        public KeyValuePairSerializable<string, string>[] OIDsXml
        {
            get
            {
                return OIDs?.Select(p => new KeyValuePairSerializable<string, string>(p)).ToArray();
            }
            set
            {
                OIDs = value?.ToDictionary(i => i.Key, i => i.Value);
            }
        }

        [XmlIgnore]
        public string CmdLine
        {
            get
            {
                string res = "";
                foreach(KeyValuePair<string, string> kvp in CmdLineArguments) 
                {
                    if (string.IsNullOrEmpty(kvp.Key)) continue;
                    if (kvp.Key.StartsWith("!")) continue;
                    if (kvp.Key.StartsWith(" ")) continue;
                    if (kvp.Key == "-n") continue;
                    if (kvp.Key == "-eku") continue;
                    if (string.IsNullOrEmpty(kvp.Value)) res += $"{kvp.Key} ";
                    else res += $"{kvp.Key} {kvp.Value} ";
                };
                if (SubjectCertificateName.Count > 0)
                {
                    string nLine = "";
                    foreach (KeyValuePair<string, string> kvp in SubjectCertificateName)
                    {
                        if (string.IsNullOrEmpty(kvp.Key)) continue;
                        if (string.IsNullOrEmpty(kvp.Value)) continue;
                        if (kvp.Key.StartsWith("!")) continue;
                        if (kvp.Key.StartsWith(" ")) continue;
                        if (string.IsNullOrEmpty(kvp.Value)) continue;
                        if (kvp.Key.Contains(",")) continue;
                        if (kvp.Value.Contains(",")) continue;
                        else nLine += $"{kvp.Key}={kvp.Value},";
                    };
                    nLine = nLine.Trim(',');
                    res += $"-n \"{nLine}\" ";
                };
                if (OIDs.Count > 0)
                {
                    string ekuLine = "";
                    foreach (KeyValuePair<string, string> kvp in OIDs)
                    {
                        if (string.IsNullOrEmpty(kvp.Key)) continue;
                        if (kvp.Key.StartsWith("!")) continue;
                        if (kvp.Key.StartsWith(" ")) continue;
                        if (kvp.Key.Contains(",")) continue;
                        else ekuLine += $"{kvp.Key},";
                    };
                    ekuLine = ekuLine.Trim(',');
                    res += $"-eku {ekuLine} ";
                };
                return res.TrimEnd(' ');
            }
        }

        [XmlIgnore]
        public string XML
        {
            get
            {
                XmlSerializerNamespaces ns = new XmlSerializerNamespaces(); ns.Add("", "");
                System.Xml.Serialization.XmlSerializer xs = new System.Xml.Serialization.XmlSerializer(typeof(MakeCertConfig));
                System.IO.MemoryStream ms = new MemoryStream();
                System.IO.StreamWriter writer = new StreamWriter(ms);
                xs.Serialize(writer, this, ns);
                writer.Flush();
                ms.Position = 0;
                byte[] bb = new byte[ms.Length];
                ms.Read(bb, 0, bb.Length);
                writer.Close();
                return System.Text.Encoding.UTF8.GetString(bb); ;
            }
        }

        public override string ToString() => CmdLine;

        public static MakeCertConfig Load(string file)
        {
            //try
            //{
                System.Xml.Serialization.XmlSerializer xs = new System.Xml.Serialization.XmlSerializer(typeof(MakeCertConfig));
                System.IO.StreamReader reader = System.IO.File.OpenText(file);
                MakeCertConfig c = (MakeCertConfig)xs.Deserialize(reader);
                reader.Close();
                return c;
            //}
            //catch (Exception ex) { };
            //{
            //    Type type = typeof(MakeCertConfig);
            //    System.Reflection.ConstructorInfo c = type.GetConstructor(new Type[0]);
            //    return (MakeCertConfig)c.Invoke(null);
            //};
        }

        public static MakeCertConfig Load(Stream file)
        {
            //try
            //{
            System.Xml.Serialization.XmlSerializer xs = new System.Xml.Serialization.XmlSerializer(typeof(MakeCertConfig));
            System.IO.StreamReader reader = new StreamReader(file);
            MakeCertConfig c = (MakeCertConfig)xs.Deserialize(reader);
            reader.Close();
            return c;
            //}
            //catch (Exception ex) { };
            //{
            //    Type type = typeof(MakeCertConfig);
            //    System.Reflection.ConstructorInfo c = type.GetConstructor(new Type[0]);
            //    return (MakeCertConfig)c.Invoke(null);
            //};
        }

        public static MakeCertConfig Defaults()
        {
            string fName = Path.Combine(CurrentDirectory(), "SignificatePE.xml");
            try { if (File.Exists(fName)) return MakeCertConfig.Load(fName); } catch { };

            MemoryStream ms = new MemoryStream(global::SignificatePE.Properties.Resources.xmlb);
            MakeCertConfig res = Load(ms);
            ms.Close();
            return res;
        }

        public static string CurrentDirectory()
        {
            return AppDomain.CurrentDomain.BaseDirectory;
            // return Application.StartupPath;
            // return Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
            // return Directory.GetCurrentDirectory();
            // return Environment.CurrentDirectory;
            // return Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().GetName().CodeBase);
            // return Path.GetDirectory(Application.ExecutablePath);
        }
    }
}
