using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;

namespace V3Guard;

/// <summary>Which step of the SMTP conversation failed.</summary>
public enum SmtpStage
{
    Resolve, Connect, Greet, Ehlo, StartTls, TlsHandshake,
    Auth, MailFrom, RcptTo, Data, Body, Quit, Done,
}

/// <summary>
/// Outcome of a send, carrying enough detail to say why it failed rather than
/// just that it did.
/// </summary>
public sealed record SmtpResult(bool Ok, SmtpStage Stage, string Detail, int Code = 0, string Reply = "")
{
    public static SmtpResult Sent() => new(true, SmtpStage.Done, "sent");

    public static SmtpResult Fail(SmtpStage stage, string detail, int code = 0, string reply = "")
        => new(false, stage, detail, code, reply);

    /// <summary>One-line summary for the log.</summary>
    public string Summary => Ok
        ? "sent"
        : $"{Stage.ToString().ToUpperInvariant()} failed: {Detail}"
          + (Code > 0 ? $" (server said {Code}{(Reply.Length > 0 ? " " + Reply : "")})" : "");

    /// <summary>
    /// A plain-language next step for the common failures, so the operator is not
    /// left looking up what a code means.
    /// </summary>
    public string Hint => Ok ? "" : Stage switch
    {
        SmtpStage.Resolve => "Check the SMTP host name. It could not be resolved.",
        SmtpStage.Connect => "Check the SMTP host and port, and that the relay is reachable.",
        SmtpStage.TlsHandshake => "TLS could not be established. If the relay does not offer it, set encryption to None.",
        SmtpStage.StartTls => "The server refused STARTTLS. Try port 465, or set encryption to None.",
        SmtpStage.Auth => Code switch
        {
            535 => "The server rejected the username or password.",
            534 or 530 => "The server wants an app password or OAuth rather than your normal password.",
            _ => "Authentication failed. Check the username and password.",
        },
        SmtpStage.MailFrom => "The sender was rejected. It usually must be the same mailbox as the SMTP account.",
        SmtpStage.RcptTo => "Every recipient was rejected. Check the To address.",
        SmtpStage.Data or SmtpStage.Body => "The server refused the message. This is often a spam filter.",
        _ => "",
    };
}

/// <summary>
/// Minimal SMTP client built directly on a socket.
///
/// Replies are read a byte at a time rather than through a buffered reader. A
/// buffered reader over-reads the socket, which has two effects: a multi-line
/// EHLO reply is only partly consumed, and leftover bytes are taken from the
/// socket before the TLS handshake begins, so SslStream sees a corrupt record
/// and fails with an internal frame error.
/// </summary>
public sealed class Mailer
{
    private readonly AppSettings _cfg;
    private readonly SemaphoreSlim _gate = new(1, 1);

    /// <summary>Server replies are truncated so one hostile response cannot flood the log.</summary>
    private const int MaxReplyChars = 200;

    public Mailer(AppSettings cfg) => _cfg = cfg;

    public SmtpResult Send(string subject, string htmlBody)
    {
        if (!_cfg.MailEnabled) return SmtpResult.Fail(SmtpStage.Done, "notifications are disabled");
        if (string.IsNullOrWhiteSpace(_cfg.SmtpHost)) return SmtpResult.Fail(SmtpStage.Done, "no SMTP host configured");
        if (string.IsNullOrWhiteSpace(_cfg.MailTo)) return SmtpResult.Fail(SmtpStage.Done, "no recipient configured");
        if (string.IsNullOrWhiteSpace(_cfg.MailFrom)) return SmtpResult.Fail(SmtpStage.Done, "no sender address configured");

        // One send at a time keeps ordering sane and avoids a connection storm
        // against the relay.
        _gate.Wait();
        try
        {
            var r = SendCore(subject, htmlBody);
            if (r.Ok)
            {
                Log.Info($"email sent to {_cfg.MailTo}");
            }
            else
            {
                Log.Error($"email NOT sent: {r.Summary}");
                if (r.Hint.Length > 0) Log.Warn($"  -> {r.Hint}");
            }
            return r;
        }
        catch (Exception ex)
        {
            var r = SmtpResult.Fail(SmtpStage.Connect, $"{ex.GetType().Name}: {ex.Message}");
            Log.Error($"email NOT sent: {r.Summary}");
            if (r.Hint.Length > 0) Log.Warn($"  -> {r.Hint}");
            return r;
        }
        finally
        {
            _gate.Release();
        }
    }

    private SmtpResult SendCore(string subject, string htmlBody)
    {
        using var client = new TcpClient();

        try
        {
            client.Connect(_cfg.SmtpHost, _cfg.SmtpPort);
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.HostNotFound)
        {
            return SmtpResult.Fail(SmtpStage.Resolve, $"host '{_cfg.SmtpHost}' not found");
        }
        catch (SocketException ex)
        {
            return SmtpResult.Fail(SmtpStage.Connect,
                $"{ex.SocketErrorCode} connecting to {_cfg.SmtpHost}:{_cfg.SmtpPort}");
        }

        client.ReceiveTimeout = 20000;
        client.SendTimeout = 20000;

        using var netStream = client.GetStream();
        Stream io = netStream;
        SslStream? ssl = null;

        try
        {
            // ---- unbuffered line I/O over whatever stream is current ----------

            string? ReadLine()
            {
                var sb = new StringBuilder(256);
                while (true)
                {
                    int b;
                    try { b = io.ReadByte(); }
                    catch (IOException) { return sb.Length > 0 ? sb.ToString() : null; }
                    if (b < 0) return sb.Length > 0 ? sb.ToString() : null;
                    if (b == '\n')
                    {
                        if (sb.Length > 0 && sb[^1] == '\r') sb.Length--;
                        return sb.ToString();
                    }
                    sb.Append((char)b);
                }
            }

            void SendLine(string s)
            {
                var bytes = Encoding.ASCII.GetBytes(s + "\r\n");
                io.Write(bytes, 0, bytes.Length);
                io.Flush();
            }

            /// Reads a complete reply, following multi-line continuations.
            int ReadReply(out string full)
            {
                var sb = new StringBuilder(256);
                int code = -1;
                while (true)
                {
                    string? line = ReadLine();
                    if (line is null) break;
                    if (sb.Length > 0) sb.Append(" | ");
                    sb.Append(line);
                    if (line.Length >= 3 && int.TryParse(line[..3], out var c)) code = c;
                    // A hyphen in the fourth column means more lines follow.
                    if (line.Length < 4 || line[3] != '-') break;
                }
                full = sb.ToString();
                return code;
            }

            bool Expect(int want, SmtpStage stage, out SmtpResult failure)
            {
                failure = SmtpResult.Sent();
                int code = ReadReply(out string full);
                if (code < 0)
                {
                    failure = SmtpResult.Fail(stage, "no response from the server (timed out?)");
                    return false;
                }
                string shown = full.Length > MaxReplyChars ? full[..MaxReplyChars] : full;
                // Accept the whole class: a server may legitimately answer EHLO
                // with any 2xx.
                if (code / 100 != want / 100)
                {
                    failure = SmtpResult.Fail(stage, "unexpected reply", code, shown);
                    return false;
                }
                return true;
            }

            // ---- conversation -------------------------------------------------

            // Port 465 is implicit TLS: the handshake happens before any plaintext.
            if (_cfg.SmtpTls && _cfg.SmtpPort == 465)
            {
                try
                {
                    ssl = new SslStream(netStream, leaveInnerStreamOpen: false);
                    ssl.AuthenticateAsClient(new SslClientAuthenticationOptions { TargetHost = _cfg.SmtpHost });
                    io = ssl;
                }
                catch (Exception ex) when (ex is AuthenticationException or IOException)
                {
                    return SmtpResult.Fail(SmtpStage.TlsHandshake, $"TLS on port 465 failed: {ex.Message}");
                }
            }

            if (!Expect(220, SmtpStage.Greet, out var f)) return f;

            SendLine($"EHLO {LocalHostName()}");
            if (!Expect(250, SmtpStage.Ehlo, out f)) return f;

            if (_cfg.SmtpTls && ssl is null)
            {
                SendLine("STARTTLS");
                if (!Expect(220, SmtpStage.StartTls, out f)) return f;

                try
                {
                    ssl = new SslStream(netStream, leaveInnerStreamOpen: false);
                    ssl.AuthenticateAsClient(new SslClientAuthenticationOptions { TargetHost = _cfg.SmtpHost });
                    io = ssl;
                }
                catch (Exception ex) when (ex is AuthenticationException or IOException)
                {
                    return SmtpResult.Fail(SmtpStage.TlsHandshake, $"STARTTLS handshake failed: {ex.Message}");
                }

                // Capabilities announced before STARTTLS are void; EHLO again.
                SendLine($"EHLO {LocalHostName()}");
                if (!Expect(250, SmtpStage.Ehlo, out f)) return f;
            }

            if (!string.IsNullOrWhiteSpace(_cfg.SmtpUser))
            {
                SendLine("AUTH LOGIN");
                if (!Expect(334, SmtpStage.Auth, out f)) return f;

                SendLine(Convert.ToBase64String(Encoding.ASCII.GetBytes(_cfg.SmtpUser)));
                if (!Expect(334, SmtpStage.Auth, out f)) return f;

                SendLine(Convert.ToBase64String(Encoding.ASCII.GetBytes(_cfg.SmtpPassword)));
                if (!Expect(235, SmtpStage.Auth, out f)) return f;
            }

            var recipients = Split(_cfg.MailTo)
                .Concat(Split(_cfg.MailCc))
                .Concat(Split(_cfg.MailBcc))
                .ToList();
            if (recipients.Count == 0)
                return SmtpResult.Fail(SmtpStage.RcptTo,
                    "no recipients could be parsed from the To/Cc/Bcc fields");

            SendLine($"MAIL FROM:<{_cfg.MailFrom}>");
            if (!Expect(250, SmtpStage.MailFrom, out f)) return f;

            int accepted = 0;
            int lastRcptCode = 0;
            string lastRcptReply = "";
            foreach (var rcpt in recipients)
            {
                SendLine($"RCPT TO:<{rcpt}>");
                int code = ReadReply(out string full);
                if (code is >= 200 and < 300)
                {
                    accepted++;
                }
                else
                {
                    lastRcptCode = code;
                    lastRcptReply = full.Length > MaxReplyChars ? full[..MaxReplyChars] : full;
                    Log.Warn($"recipient rejected: {rcpt} ({lastRcptReply})");
                }
            }
            if (accepted == 0)
                return SmtpResult.Fail(SmtpStage.RcptTo,
                    $"all {recipients.Count} recipient(s) rejected", lastRcptCode, lastRcptReply);

            SendLine("DATA");
            if (!Expect(354, SmtpStage.Data, out f)) return f;

            foreach (var line in BuildMessage(subject, htmlBody).Split('\n'))
            {
                var l = line.TrimEnd('\r');
                // Dot-stuffing: a line beginning with '.' must be escaped.
                SendLine(l.StartsWith('.') ? "." + l : l);
            }
            SendLine(".");
            if (!Expect(250, SmtpStage.Body, out f)) return f;

            try
            {
                SendLine("QUIT");
                ReadReply(out _);
            }
            catch { /* nothing depends on the farewell succeeding */ }

            return SmtpResult.Sent();
        }
        finally
        {
            ssl?.Dispose();
        }
    }

    private static string LocalHostName()
    {
        try { return Dns.GetHostName(); }
        catch { return "localhost"; }
    }

    /// <summary>Builds the MIME message. Bcc is envelope-only and never disclosed.</summary>
    private string BuildMessage(string subject, string htmlBody)
    {
        var sb = new StringBuilder(8192);
        sb.Append($"From: {_cfg.MailFrom}\r\n");
        sb.Append($"To: {_cfg.MailTo}\r\n");
        if (!string.IsNullOrWhiteSpace(_cfg.MailCc)) sb.Append($"Cc: {_cfg.MailCc}\r\n");
        // Bcc deliberately has no header: those recipients are added at the envelope.
        sb.Append($"Subject: {Sanitize.SingleLine(subject, 160)}\r\n");
        sb.Append($"Date: {DateTime.Now:R}\r\n");
        sb.Append("MIME-Version: 1.0\r\n");
        sb.Append("Content-Type: text/html; charset=utf-8\r\n\r\n");
        sb.Append(htmlBody);
        return sb.ToString();
    }

    private static IEnumerable<string> Split(string s) =>
        s.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}