/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using Microsoft.Owin;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace Thinktecture.IdentityModel.Owin
{
    public class RequireSslMiddleware
    {
        readonly Func<IDictionary<string, object>, Task> _next;
        private RequireSslOptions _options;

        public RequireSslMiddleware(Func<IDictionary<string, object>, Task> next, RequireSslOptions options)
        {
            _next = next;
            _options = options;
        }

        public async Task Invoke(IDictionary<string, object> env)
        {
            var context = new OwinContext(env);

            if (context.Request.Uri.Scheme != Uri.UriSchemeHttps)
            {
                if (_options.AllowHttp) return;
                
                context.Response.StatusCode = 403;
                context.Response.ReasonPhrase = "SSL is required.";
                if (_options.WriteReasonToContent)
                    context.Response.Write(context.Response.ReasonPhrase);
                return;
            }

            if (_options.RequireClientCertificate)
            {
                var cert = context.Get<X509Certificate2>("ssl.ClientCertificate");
                if (cert == null)
                {
                    if (context.Environment.ContainsKey("ssl.ClientCertificateErrors"))
                    {
                        var errors = context.Environment["ssl.ClientCertificateErrors"];
                        var loadFunc = (System.Func<System.Threading.Tasks.Task>)context.Environment["ssl.LoadClientCertAsync"];
                        var t = loadFunc();
                        await t;
                    }
                    context.Response.StatusCode = 401;
                    context.Response.ReasonPhrase = "SSL client certificate is required.";
                    if (_options.WriteReasonToContent)
                        context.Response.Write(context.Response.ReasonPhrase);
                    return;
                }

                if (_options.RequiredCertificateIssuer != null)
                {
                    if (cert.IssuerName.Name != _options.RequiredCertificateIssuer)
                    {
                        context.Response.StatusCode = 401;
                        context.Response.ReasonPhrase = string.Format("SSL client certificate issued by a concrete issuer is required. Your issuer: {0}", cert.IssuerName.Name);
                        if (_options.WriteReasonToContent)
                            context.Response.Write(context.Response.ReasonPhrase);
                        return;
                    }
                }
            }

            await _next(env);
        }
    }
}