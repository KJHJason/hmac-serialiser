using    System;

namespace    HMACSerialiser.Base64Encoders
{
                public    static    class    URLSafeBase64Encoder
                {
                                public    static    string    Base64Encode(byte[]    data)
                                {
                                                string    base64    =    Convert.ToBase64String(data);
                                                return    base64.Replace('+',    '-').Replace('/',    '_');
                                }

                                public    static    byte[]    Base64Decode(string    data)
                                {
                                                string    incoming    =    data.Replace('_',    '/').Replace('-',    '+');

                                                //    Just    in    case,    check    if    the
                                                //    length    is    valid    base64    length.    If    not,    add    padding
                                                switch    (data.Length    %    4)
                                                {
                                                                case    2:    incoming    +=    "==";    break;
                                                                case    3:    incoming    +=    "=";    break;
                                                }

                                                byte[]    bytes    =    Convert.FromBase64String(incoming);
                                                return    bytes;
                                }

                                public    static    bool    ContainsBase64Chars(string    data)
                                {
                                                foreach    (char    c    in    data)
                                                {
                                                                //    characters:    [^A-Za-z0-9-_=]
                                                                if    (char.IsLetterOrDigit(c)    ||    c    ==    '-'    ||    c    ==    '_'    ||    c    ==    '=')
                                                                                return    true;
                                                }
                                                return    false;
                                }
                }
}
