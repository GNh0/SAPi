using System.Text;
using System.Web;
using System.Web.Routing;
using SApi.Protocol;

namespace SApi.AspNet;

public sealed class SapiHttpHandler : HttpTaskAsyncHandler
{
    private readonly SecureServer server;
    public SapiHttpHandler(SecureServer server) {this.server=server ?? throw new ArgumentNullException(nameof(server));}
    public override bool IsReusable => true;
    public override async Task ProcessRequestAsync(HttpContext context)
    {
        context.Response.TrySkipIisCustomErrors=true;context.Response.BufferOutput=true;
        context.Response.Cache.SetCacheability(HttpCacheability.NoCache);context.Response.Cache.SetNoStore();
        context.Response.Headers["X-Content-Type-Options"]="nosniff";
        if(context.Request.HttpMethod!="POST" || context.Request.AppRelativeCurrentExecutionFilePath!="~/sapi" || context.Request.PathInfo.Length!=0 || context.Request.Url.Query.Length!=0 || context.Request.ContentType!="application/sapi+jwe" || context.Request.Headers["Authorization"]!=null || context.Request.ContentLength>Codec.MaxWire)
        {context.Response.StatusCode=400;return;}
        try
        {
            using var deadline=CancellationTokenSource.CreateLinkedTokenSource(context.Response.ClientDisconnectedToken);deadline.CancelAfter(TimeSpan.FromSeconds(30));
            var bytes=new byte[Codec.MaxWire+1];var count=0;
            while(count<bytes.Length){var n=await context.Request.InputStream.ReadAsync(bytes,count,bytes.Length-count,deadline.Token).ConfigureAwait(false);if(n==0)break;count+=n;}
            if(count>Codec.MaxWire)throw new SapiException();for(var n=0;n<count;n++)if(bytes[n]>127)throw new SapiException();
            deadline.Token.ThrowIfCancellationRequested();
            var response=server.Handle(Encoding.ASCII.GetString(bytes,0,count));context.Response.ContentType="application/sapi+jwe";
            await context.Response.Output.WriteAsync(response).ConfigureAwait(false);
        }
        catch {context.Response.ClearContent();context.Response.StatusCode=400;}
    }
}

public static class RouteExtensions
{
    private sealed class HandlerRoute : IRouteHandler
    {
        private readonly SapiHttpHandler handler;
        internal HandlerRoute(SecureServer server) {handler=new SapiHttpHandler(server);}
        public IHttpHandler GetHttpHandler(System.Web.Routing.RequestContext context) => handler;
    }
    public static void MapSapi(this RouteCollection routes, SecureServer server)
    {routes.Add("SAPi",new Route("sapi",new HandlerRoute(server)));}
}
