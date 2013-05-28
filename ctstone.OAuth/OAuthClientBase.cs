using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;

namespace ctstone.OAuth
{
    public class OAuthEventArgs : EventArgs
    {
        public OAuthEventArgs(Uri authorizationUri)
        {
            AuthorizationUri = authorizationUri;
        }
        public Uri AuthorizationUri { get; private set; }
    }

    public class OAuthRequestTokenEventArgs : EventArgs
    {
        public OAuthRequestTokenEventArgs(FormParameters form)
        {
            Parameters = form;
        }
        public FormParameters Parameters { get; private set; }
    }

    public abstract class OAuthClientBase
    {
        private const string UnreservedCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
        public readonly string ConsumerKey;
        public readonly string SharedSecret;
        public readonly string CallbackUrl;
        protected FormParameters _protocolParameters;
        private int _authCount;
        private static DateTime _epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        public string AuthorizedToken { get; private set; }
        public string AuthorizedTokenSecret { get; private set; }
        public bool IsAuthorized { get { return !String.IsNullOrEmpty(AuthorizedTokenSecret); } }
        protected abstract Uri TemporaryCredentialsUri { get; }
        protected abstract Uri AuthorizeUri { get; }
        protected abstract Uri AccessTokenUri { get; }
        public event EventHandler<OAuthEventArgs> AuthorizationRequired;
        protected event EventHandler<OAuthRequestTokenEventArgs> TempTokenRequesting;

        protected virtual string TempTokenMethod
        {
            get { return "POST"; }
        }

        protected virtual string AccessTokenMethod
        {
            get { return "POST"; }
        }

        protected virtual string SignatureMethod
        {
            get { return "HMAC-SHA1"; }
        }

        public OAuthClientBase(string consumerKey, string sharedSecret, string callbackUrl)
            : this(consumerKey, sharedSecret, callbackUrl, String.Empty, String.Empty)
        { }

        public OAuthClientBase(string consumerKey, string sharedSecret, string callbackUrl, string authorizedToken, string authorizedTokenSecret)
        {
            ConsumerKey = consumerKey;
            SharedSecret = sharedSecret;
            CallbackUrl = callbackUrl;
            AuthorizedToken = authorizedToken;
            AuthorizedTokenSecret = authorizedTokenSecret;
            _protocolParameters = new FormParameters();
        }

        public void Verify(string verifier)
        {
            _protocolParameters.Set("oauth_verifier", verifier);

            // TODO: check AccessTokenMethod

            HttpWebResponse response = AuthorizedPOST(AccessTokenUri);
            using (var sr = new StreamReader(response.GetResponseStream()))
            {
                var text = sr.ReadToEnd();
                FormParameters reply = FormParameters.OAuthDecode(text);
                AuthorizedToken = reply["oauth_token"];
                AuthorizedTokenSecret = reply["oauth_token_secret"];
                
                // TODO pass additional parameters to impl
            }
        }

        private void SetTempToken()
        {
            FormParameters form = new FormParameters();
            if (TempTokenRequesting != null)
                TempTokenRequesting(this, new OAuthRequestTokenEventArgs(form));
            //_protocolParameters.Set("oauth_callback", CallbackUrl);
            form.Add("oauth_callback", CallbackUrl);

            // TODO: check TempTokenMethod

            HttpWebResponse response = AuthorizedPOST(TemporaryCredentialsUri, form);
            using (var sr = new StreamReader(response.GetResponseStream()))
            {
                string text = sr.ReadToEnd();
                FormParameters reply = FormParameters.OAuthDecode(text);
                AuthorizedToken = reply["oauth_token"];
                AuthorizedTokenSecret = reply["oauth_token_secret"];

                // TODO pass additional parameters to impl
            }
        }

        private Uri GetAuthorizationUri()
        {
            return new Uri(AuthorizeUri, "?oauth_token=" + AuthorizedToken);
        }

        protected HttpWebResponse AuthorizedGET(Uri uri)
        {
            Trace.WriteLine("GET " + uri);
            HttpWebRequest request = WebRequest.CreateHttp(uri);
            request.Method = "GET";
            Authorize(request);
            return GetResponse(request);
        }

        protected HttpWebResponse AuthorizedPOST(Uri uri, FormParameters parameters = null)
        {
            Trace.WriteLine("POST " + uri);

            if (parameters == null)
                parameters = new FormParameters();

            HttpWebRequest request = WebRequest.CreateHttp(uri);
            request.Method = "POST";
            request.ContentType = "application/x-www-form-urlencoded";
            Authorize(request, parameters);

            string data = parameters.FormEncode();
            Trace.WriteLine("POST payload: " + data);
            return GetResponse(request, Encoding.UTF8.GetBytes(data));
        }

        protected HttpWebResponse GetResponse(HttpWebRequest request, byte[] data = null)
        {
            request.AllowAutoRedirect = false;
            if (data != null && data.Length > 0)
            {
                request.ContentLength = data.Length;
                using (var stream = request.GetRequestStream())
                {
                    stream.Write(data, 0, data.Length);
                }
            }

            HttpWebResponse response;
            try
            {
                response = request.GetResponse() as HttpWebResponse;
            }
            catch (WebException e)
            {
                response = e.Response as HttpWebResponse;
            }

            if (response == null)
                throw new Exception("No response");

            _protocolParameters.Clear();

            if (response.StatusCode == HttpStatusCode.Unauthorized && AuthorizationRequired != null && _authCount == 0)
            {
                Trace.WriteLine("Authorizing");
                _authCount++;
                using (var sr = new StreamReader(response.GetResponseStream()))
                {
                    var text = sr.ReadToEnd();
                }
                SetTempToken();
                AuthorizationRequired(this, new OAuthEventArgs(GetAuthorizationUri()));
                return ResendRequest(request, data);
            }


            return response;
        }

        private HttpWebResponse ResendRequest(HttpWebRequest request, byte[] data)
        {
            if (request.Method == "GET")
                return AuthorizedGET(request.RequestUri);

            if (request.Method == "POST" && request.ContentType == "application/x-www-form-urlencoded")
            {
                FormParameters form = FormParameters.FormDecode(Encoding.UTF8.GetString(data));
                return AuthorizedPOST(request.RequestUri, form);
            }

            throw new NotImplementedException();
        }

        protected virtual string Sign(string secret, string signature)
        {
            if (SignatureMethod != "HMAC-SHA1")
                throw new NotSupportedException("Signature method not supported: " + SignatureMethod);

            return ComputeHMACSHA1(secret, signature);
        }

        private void Authorize(HttpWebRequest request, FormParameters parameters = null)
        {
            if (parameters == null)
                parameters = new FormParameters();

            _protocolParameters.Set("oauth_consumer_key", ConsumerKey);
            _protocolParameters.Set("oauth_token", AuthorizedToken);
            _protocolParameters.Set("oauth_signature_method", SignatureMethod);
            _protocolParameters.Set("oauth_timestamp", GenerateTimestamp());
            _protocolParameters.Set("oauth_nonce", GenerateNonce());
            _protocolParameters.Set("oauth_version", "1.0");
            _protocolParameters.Set("oauth_signature", GenerateSignature(request, parameters));

            string auth = _protocolParameters.HeaderEncode();
            Trace.WriteLine("Authorization: " + auth);
            request.Headers["Authorization"] = auth;
        }

        private string GenerateSignature(HttpWebRequest request, FormParameters formParameters)
        {
            FormParameters parameters = FormParameters.OAuthDecode(request.RequestUri.Query);
            foreach (var item in _protocolParameters)
                parameters.Add(item);
            if (request.ContentType == "application/x-www-form-urlencoded")
            {
                foreach (var item in formParameters)
                    parameters.Add(item);
            }
            parameters.Sort();

            string signature = GenerateBaseSignature(request.Method, request.RequestUri, parameters);
            string secret = EncodeSecret();

            Trace.WriteLine("Secret: " + secret);
            Trace.WriteLine("Signature: " + signature);

            return Sign(secret, signature);
        }

        private string EncodeSecret()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append(Encode(SharedSecret));
            sb.Append('&');
            sb.Append(Encode(AuthorizedTokenSecret));
            return sb.ToString();
        }

        private static string GenerateNonce()
        {
            Random r = new Random();
            byte[] buffer = new byte[8];
            r.NextBytes(buffer);
            StringBuilder sb = new StringBuilder(buffer.Length * 2);
            foreach (var b in buffer)
                sb.Append(b.ToString("x2"));
            return sb.ToString();
        }

        private static string GenerateBaseSignature(string method, Uri uri, FormParameters sortedParameters)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append(Encode(method.ToUpper()));
            sb.Append('&');
            sb.Append(Encode(uri.Scheme.ToLower()));
            sb.Append(Encode("://"));
            sb.Append(Encode(uri.Host.ToLower()));
            if (!uri.IsDefaultPort)
                sb.Append(uri.Port);
            sb.Append(Encode(uri.AbsolutePath));
            sb.Append('&');
            sb.Append(sortedParameters.SignatureEncode());
            return sb.ToString();
        }

        private static string GenerateTimestamp()
        {
            return (DateTime.UtcNow - _epoch).TotalSeconds.ToString("F0");
        }

        private static byte[] ComputeHMACSHA1(byte[] key, byte[] data)
        {
            using (HMACSHA1 sha1 = new HMACSHA1(key))
            {
                return sha1.ComputeHash(data);
            }
        }

        private static string ComputeHMACSHA1(string key, string data)
        {
            return Convert.ToBase64String(ComputeHMACSHA1(Encoding.UTF8.GetBytes(key), Encoding.UTF8.GetBytes(data)));
        }

        public static string Encode(string input, Encoding encoding = null)
        {
            if (String.IsNullOrEmpty(input))
                return String.Empty;

            if (encoding == null)
                encoding = Encoding.UTF8;

            return Encode(encoding.GetBytes(input));
        }

        public static string Encode(byte[] input)
        {
            StringBuilder sb = new StringBuilder();
            foreach (char c in input)
            {
                if (UnreservedCharacters.IndexOf(c) == -1)
                    sb.AppendFormat("%{0:X2}", (byte)c);
                else
                    sb.Append(c);
            }
            return sb.ToString();
        }

        public static string Decode(string input, int fromBase = 16)
        {
            if (String.IsNullOrEmpty(input))
                return String.Empty;

            int size = fromBase / 8; // 8 bits in byte
            return Regex.Replace(input, "%[0-9A-F]{" + size + "}", m =>
            {
                string hex = m.Value.Substring(1);
                return ((char)Convert.ToInt32(hex, fromBase)).ToString();
            });
        }

    }

    public class FormParameters : IEnumerable<KeyValuePair<string, byte[]>>
    {
        private List<KeyValuePair<string, byte[]>> _parameters;
        private static OAuthParameterComparer _comparer 
            = new OAuthParameterComparer();

        public int Count 
        { get { return _parameters.Count; } }

        public KeyValuePair<string, byte[]> this[int i] 
        { get { return _parameters[i]; } }

        public string this[string key] // TODO: rename to GetFirst(k, enc)
        {
            get
            {
                foreach (var item in this)
                {
                    if (item.Key == key)
                        return Encoding.UTF8.GetString(item.Value);
                }
                return String.Empty;
            }
        }

        public FormParameters()
        {
            _parameters = new List<KeyValuePair<string, byte[]>>();
        }

        public static FormParameters OAuthDecode(string message)
        {
            FormParameters form = new FormParameters();
            message = message.TrimStart('?');
            if (String.IsNullOrWhiteSpace(message))
                return form;
            foreach (var pair in message.Split('&'))
            {
                string[] parts = pair.Split('=');
                string key = OAuthClientBase.Decode(parts[0]);
                string value = parts.Length > 1
                    ? OAuthClientBase.Decode(parts[1])
                    : String.Empty;
                form.Add(key, value);
            }
            return form;
        }

        public static FormParameters FormDecode(string message)
        {
            FormParameters form = new FormParameters();
            if (String.IsNullOrWhiteSpace(message))
                return form;
            foreach (var pair in message.Split('&'))
            {
                string[] parts = pair.Split('=');
                string key = HttpUtility.UrlDecode(parts[0], Encoding.UTF8);
                string value = parts.Length > 1
                    ? HttpUtility.UrlDecode(parts[1], Encoding.UTF8)
                    : String.Empty;
                form.Add(key, value);
            }
            return form;
        }

        public void Remove(string key)
        {
            for (int i = 0; i < Count; i++)
            {
                if (this[i].Key == key)
                    _parameters.RemoveAt(i);
            }
        }

        public void Set(string key, byte[] value)
        {
            Remove(key);
            Add(key, value);
        }

        public void Set(string key, string value, Encoding encoding = null)
        {
            if (encoding == null)
                encoding = Encoding.UTF8;
            Set(key, encoding.GetBytes(value));
        }

        public void Set(string key, object value)
        {
            Set(key, value.ToString());
        }

        public void Add(string key, object value)
        {
            if (value == null)
                return;
            Add(key, value.ToString());
        }

        public void Add(string key, string value, Encoding encoding = null)
        {
            if (value == null)
                return;
            if (encoding == null)
                encoding = Encoding.UTF8;
            Add(key, encoding.GetBytes(value));
        }
        public void Add(string key, byte[] value)
        {
            if (value == null)
                return;
            _parameters.Add(new KeyValuePair<string, byte[]>(key, value));
        }

        public void Add(KeyValuePair<string, byte[]> item) 
        {
            _parameters.Add(item);
        }

        public void Sort()
        {
            _parameters.Sort(_comparer);
        }

        public void Clear()
        {
            _parameters.Clear();
        }

        public string SignatureEncode(Encoding encoding = null)
        {
            if (encoding == null)
                encoding = Encoding.UTF8;

            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < Count; i++)
            {
                // tumblr does not correctly handle encoded parameter names :(
                //sb.Append(OAuthClientBase.Encode(this[i].Key, encoding));
                sb.Append(this[i].Key); // workaround for tumblr
                sb.Append('=');
                sb.Append(OAuthClientBase.Encode(this[i].Value));
                if (i < Count - 1)
                    sb.Append('&');
            }
            return OAuthClientBase.Encode(sb.ToString());
        }

        public string HeaderEncode(Encoding encoding = null)
        {
            if (encoding == null)
                encoding = Encoding.UTF8;

            StringBuilder sb = new StringBuilder();
            sb.Append(@"OAuth "); // TODO: realm
            for (int i = 0; i < Count; i++)
            {
                sb.Append(OAuthClientBase.Encode(this[i].Key, encoding));
                sb.Append('=');
                sb.Append('"');
                sb.Append(OAuthClientBase.Encode(this[i].Value));
                sb.Append('"');
                if (i < Count - 1)
                    sb.Append(',');
            }
            return sb.ToString();
        }

        public string FormEncode(Encoding encoding = null)
        {
            if (encoding == null)
                encoding = Encoding.UTF8;

            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < Count; i++)
            {
                sb.Append(HttpUtility.UrlEncode(this[i].Key, encoding));
                sb.Append('=');
                sb.Append(HttpUtility.UrlEncode(this[i].Value));
                if (i < Count - 1)
                    sb.Append('&');
            }
            return sb.ToString();
        }

        public override string ToString()
        {
            return ToString(Encoding.UTF8);
        }

        public string ToString(Encoding encoding)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < Count; i++)
            {
                if (this[i].Value == null)
                    continue;

                sb.Append(this[i].Key);
                sb.Append('=');
                sb.Append(encoding.GetString(this[i].Value));
                if (i < Count - 1)
                    sb.Append('&');
            }
            if (sb.Length > 0)
                sb.Insert(0, '?');
            return sb.ToString();
        }

        public IEnumerator<KeyValuePair<string, byte[]>> GetEnumerator()
        {
            return _parameters.GetEnumerator();
        }

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        class OAuthParameterComparer : IComparer<KeyValuePair<string, byte[]>>
        {
            public int Compare(KeyValuePair<string, byte[]> x, KeyValuePair<string, byte[]> y)
            {
                if (x.Key == y.Key)
                    return Compare(x.Value, y.Value);

                return String.CompareOrdinal(x.Key, y.Key);
            }

            private static int Compare(byte[] x, byte[] y)
            {
                for (int i = 0; i < x.Length; i++)
                {
                    if (i > y.Length)
                        return 1; // x > y

                    int comparison = x[i].CompareTo(y[i]);
                    if (comparison != 0)
                        return comparison;
                }

                return -1; // x < y
            }
        }
    }
}
