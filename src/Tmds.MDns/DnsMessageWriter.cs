//Copyright (C) 2013  Tom Deseyn

//This library is free software; you can redistribute it and/or
//modify it under the terms of the GNU Lesser General Public
//License as published by the Free Software Foundation; either
//version 2.1 of the License, or (at your option) any later version.

//This library is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//Lesser General Public License for more details.

//You should have received a copy of the GNU Lesser General Public
//License along with this library; if not, write to the Free Software
//Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;

namespace Tmds.MDns
{
    public class DnsMessageWriter
    {
        public DnsMessageWriter()
        {
            _stream = new MemoryStream(_buffer);
        }

        public void Reset()
        {
            _stream.Seek(0, SeekOrigin.Begin);
            _questionCount = 0;
            _answerCount = 0;
            _authorityCount = 0;
            _additionalCount = 0;
            _recordStartPosition = 0;
        }

        public class ResponseFlags
        {
            public enum MessageType { Response, Answer }
            public MessageType Type { get; set; }
            private byte opCode;

            public byte OpCode
            {
                get { return opCode; }
                set {
                    byte source = value;
                    byte hiNibble = (byte)((source & 0xF0) >> 4); //Left hand 
                    if (hiNibble > 0)
                    {
                        throw new ArgumentOutOfRangeException("OpCode is 4 bits only!");
                    }
                    byte loNiblle = (byte)(source & 0x0F);      //Right hand 
                    opCode = loNiblle; }
            }
            public bool Authoritative { get; set; }
            public bool Truncated { get; set; }
            public bool RecursionDesired { get; set; }
            public bool RecursionAvailable { get; set; }
            public bool Z { get; set; }

            /// <summary>
            /// For response only!
            /// </summary>
            public bool AnswerAuthenticated { get; set; }
            public bool NonAuthenticatedData { get; set; }
            private byte replyCode;

            /// <summary>
            /// For response only!
            /// </summary>
            public byte ReplyCode
            {
                get { return replyCode; }
                set
                {
                    byte source = value;
                    byte hiNibble = (byte)((source & 0xF0) >> 4); //Left hand 
                    if (hiNibble > 0)
                    {
                        throw new ArgumentOutOfRangeException("ReplyCode is 4 bits only!");
                    }
                    byte loNiblle = (byte)(source & 0x0F);      //Right hand 
                    replyCode = loNiblle;
                }
            }

            internal ushort AsUInt16()
            {
                ushort flags = this.Type == MessageType.Response ? (ushort)(1 << 15) : (ushort)0;
                flags |= (ushort)(opCode << 11);
                flags |= Authoritative? (ushort)(1 << 10) : (ushort)0;
                flags |= Truncated? (ushort)(1 << 9) : (ushort)0;
                flags |= RecursionDesired? (ushort)(1 << 8) : (ushort)0;
                flags |= RecursionAvailable? (ushort)(1 << 7) : (ushort)0;
                flags |= Z? (ushort)(1 << 6) : (ushort)0;
                flags |= AnswerAuthenticated? (ushort)(1 << 5) : (ushort)0;
                flags |= NonAuthenticatedData? (ushort)(1 << 4) : (ushort)0;
                flags |= (ushort)(replyCode << 0);
                return flags;
            }
        }

        public void WriteQueryHeader(ushort transactionId, ResponseFlags responseFlags)
        {
            Debug.Assert(_stream.Position == 0);
            WriteUInt16(transactionId);
            WriteUInt16(responseFlags.AsUInt16()); // flags
            WriteUInt16(0); // questionCount
            WriteUInt16(0); // answerCount
            WriteUInt16(0); // authorityCount
            WriteUInt16(0); // additionalCount
        }

        public void WriteQuestion(Name name, RecordType qtype, RecordClass qclass = RecordClass.Internet)
        {
            WriteName(name);
            WriteUInt16((ushort)qtype);
            WriteUInt16((ushort)qclass);
            _questionCount++;
        }

        public void WritePtrRecord(RecordSection recordType, Name name, string ptrName, uint ttl, RecordClass _class = RecordClass.Internet)
        {
            WriteRecordStart(recordType, name, RecordType.PTR, ttl, _class, ptrName);
            //WriteRecordData(name);
            //WriteRecordEnd();
        }

        public void WriteTxtRecord(RecordSection recordType, uint ttl, string[] texts,
            byte srvNameOffset = 0x2B, ushort srvPriority = 0x01, ushort srvWeigth = 0x01, ushort srvPort = 9955,
            byte srvTargetNamePtrOffset = 0x1A,
            RecordClass _class = RecordClass.Internet,
            string namePrefix = null)
        {
            WriteRecordStart(recordType, null, RecordType.TXT, ttl, _class, null, srvNameOffset, srvPriority,
                srvWeigth, srvPort, "srcTargetName", srvTargetNamePtrOffset, txtContents: texts,
                 srvNamePrefix: namePrefix

                );
        }

        public void WriteSrvRecord(RecordSection recordType, uint ttl,
            byte srvNameOffset = 0x2B, ushort srvPriority = 0x01, ushort srvWeigth = 0x01, ushort srvPort = 9955, 
            string srcTargetName = "14ffxxx", byte srvTargetNamePtrOffset = 0x1A,
            RecordClass _class = RecordClass.Internet)
        {
            WriteRecordStart(recordType, null, RecordType.SRV, ttl, _class, null, srvNameOffset, srvPriority,
                srvWeigth, srvPort, srcTargetName, srvTargetNamePtrOffset
                
                );
        }
            public void WriteRecordStart(RecordSection recordType, Name name, RecordType type, uint ttl,
            RecordClass _class = RecordClass.Internet,
            string ptrName = null,
            byte? srvNameOffset = null, ushort? srvPriority = null, ushort? srvWeigth = null, ushort? srvPort = null,
            string srcTargetName = null, byte? srvTargetNamePtrOffset= null,
            string srvNamePrefix = null,
            string[] txtContents = null
            )
        {
            //Debug.Assert(_recordStartPosition == 0);
            if (type == RecordType.PTR)
            {
                WriteName(name);
                WriteUInt16((ushort)type);
                WriteUInt16((ushort)_class);
                WriteUInt32(ttl);
            
                if (ptrName == null)
                {
                    WriteUInt16(0);
                }
                else
                {
                    // Write length of rest
                    WriteUInt16((ushort)(ptrName.Length + 3));
                    // Write name with trailing pointer
                    WriteNameWithTrailingPointer(ptrName, 0x0c);
                    //WriteUInt16((ushort)(ptrName.Length + 3));
                    //WriteString255(ptrName);

                    //// FQDN is appended via pointer C0 0C -> pointing to byte 12 (WriteName(name))
                    //// 0C is FQDN of first PTR record, e.g. XX_alljoyn._tcp.local (XX is UInt for length of string)
                    //WriteByte(0xc0);
                    //WriteByte(0x0c);
                }
            }
            else if (type == RecordType.SRV || type == RecordType.TXT)
            {
                if (srvNamePrefix != null)
                {
                    WriteString255(srvNamePrefix);
                }

                WriteByte(0xc0);
                // 2B is name of first PTR record
                WriteByte(srvNameOffset.Value);
                WriteUInt16((ushort)type);
                WriteUInt16((ushort)_class);
                WriteUInt32(ttl);
                // 1A is part of FQDN of first PTR record, e.g. .local for 
                // XX_alljoyn._tcp.local (XX is UInt for length of string)
                // |<-0C          |<-1A (each part is preceded 8bits for length)

                if (type == RecordType.SRV)
                {
                    // length of rest
                    WriteUInt16((ushort)(srcTargetName.Length + 3 + 6));

                    WriteUInt16(srvPriority.Value);
                    WriteUInt16(srvWeigth.Value);
                    WriteUInt16(srvPort.Value);

                    // Write name with trailing pointer
                    WriteNameWithTrailingPointer(srcTargetName, srvTargetNamePtrOffset.Value);
                    //WriteUInt16((ushort)(srcTargetName.Length + 3));
                    //WriteString255(srcTargetName);
                    //WriteByte(0xc0);
                    //WriteByte(srvTargetNamePtrOffset.Value);
                }
                else if (type == RecordType.TXT)
                {
                    // length of rest
                    WriteUInt16((ushort)(txtContents.Sum(t => t.Length) + txtContents.Length));
                    foreach (var txtContent in txtContents)
                    {
                        WriteString255(txtContent);
                    }
                }
            }
            switch (recordType)
            {
                case RecordSection.Answer:
                    _answerCount++;
                    break;
                case RecordSection.Additional:
                    _additionalCount++;
                    break;
                case RecordSection.Authority:
                    _authorityCount++;
                    break;
            }
            _recordStartPosition = _stream.Position;
        }

        private void WriteNameWithTrailingPointer(string ptrName, byte ptrOffset)
        {
            WriteString255(ptrName);
            WriteByte(0xc0);
            WriteByte(ptrOffset);
        }

        /// <summary>
        /// Write string of max length 255.
        /// First 1 byte for length, followed by string.
        /// </summary>
        /// <param name="content"></param>
        private void WriteString255(string content)
        {
            WriteByte((byte)content.Length);
            WriteStringRaw(content);
        }

        private string PeekStream()
        {
            long currentPosition = _stream.Position;
            _stream.Seek(0, SeekOrigin.Begin);
            StreamReader reader = new StreamReader(_stream);
            string before = reader.ReadToEnd();
            _stream.Seek(currentPosition, SeekOrigin.Begin);
            return before;
        }

        private void WriteByte(byte b)
        {
            _stream.WriteByte(b);
        }

        public void WriteRecordData(byte[] buffer, int offset, int length)
        {
            Debug.Assert(_recordStartPosition != 0);
            _stream.Write(buffer, offset, length);
        }

        public void WriteRecordData(byte[] buffer)
        {
            _stream.Write(buffer, 0, buffer.Length);
        }

        public void WriteRecordData(Name name)
        {
            Debug.Assert(_recordStartPosition != 0);
            WriteName(name);
        }

        public void WriteRecordData(IPAddress address)
        {
            byte[] bytes = address.GetAddressBytes();
            WriteRecordData(bytes);
        }

        public void WriteRecordEnd()
        {
            long currentPosition = _stream.Position;
            var length = (ushort)(currentPosition - _recordStartPosition);
            _stream.Seek(_recordStartPosition - 2, SeekOrigin.Begin);
            WriteUInt16(length);
            _stream.Seek(currentPosition, SeekOrigin.Begin);
            _recordStartPosition = 0;
        }

        public IList<ArraySegment<byte>> Packets
        {
            get
            {
                Finish();
                return new List<ArraySegment<byte>>
                {
                    new ArraySegment<byte>(_buffer, 0, (int)_stream.Position)
                };
            }
        }

        private void WriteUInt16(ushort value)
        {
            _stream.WriteByte((byte)(value >> 8));
            _stream.WriteByte((byte)(value & 0xff));
        }

        private void WriteUInt32(uint value)
        {
            _stream.WriteByte((byte)((value & 0xff000000) >> 24));
            _stream.WriteByte((byte)((value & 0x00ff0000) >> 16));
            _stream.WriteByte((byte)((value & 0x0000ff00) >> 8));
            _stream.WriteByte((byte)((value & 0x000000ff) >> 0));
        }

        private void WriteStringRaw(string s)
        {
            int length = s.Length;
            Encoding.UTF8.GetBytes(s, 0, s.Length, _buffer, (int)_stream.Position);
            _stream.Seek(length, SeekOrigin.Current);
        }

            private void WriteName(Name name)
        {
            bool finished = false;
            foreach(string label in name.Labels)
            {
                int length = label.Length;
                finished = (length == 0);
                _stream.WriteByte((byte)length);
                Encoding.UTF8.GetBytes(label, 0, label.Length, _buffer, (int)_stream.Position);
                _stream.Seek(length, SeekOrigin.Current);
            }
            if (!finished)
            {
                _stream.WriteByte(0);
            }
        }

        private void Finish()
        {
            long currentPosition = _stream.Position;

            _stream.Seek(0, SeekOrigin.Begin);
            StreamReader reader = new StreamReader(_stream);
            string before = reader.ReadToEnd();

            _stream.Seek(4, SeekOrigin.Begin);
            WriteUInt16(_questionCount);
            WriteUInt16(_answerCount);
            WriteUInt16(_authorityCount);
            WriteUInt16(_additionalCount);

            _stream.Seek(0, SeekOrigin.Begin);
            StreamReader reader2 = new StreamReader(_stream);
            string after = reader2.ReadToEnd();

            _stream.Seek(currentPosition, SeekOrigin.Begin);
        }

        private readonly byte[] _buffer = new byte[9000];
        private readonly MemoryStream _stream;
        private ushort _questionCount;
        private ushort _answerCount;
        private ushort _authorityCount;
        private ushort _additionalCount;
        private long _recordStartPosition;
    }
}
