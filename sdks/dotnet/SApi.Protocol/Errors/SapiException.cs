namespace SApi.Protocol;

public sealed class SapiException : Exception
{
    public string Code { get; }
    public SapiException(string code = "invalid_message") : base(code) => Code = code;
}
