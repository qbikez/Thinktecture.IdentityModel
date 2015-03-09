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
            string reason = null;
            if (context.Request.Uri.Scheme != Uri.UriSchemeHttps)
            {
                if (!_options.AllowHttp)
                {
                    context.Response.StatusCode = 403;
                    reason = "SSL is required.";
                }
            }
            else if (_options.RequireClientCertificate)
            {
                var cert = context.Get<X509Certificate2>("ssl.ClientCertificate");
                if (cert == null)
                {
                    context.Response.StatusCode = 403;
                    reason = "SSL client certificate is required.";
                }
                else if (_options.RequiredCertificateIssuer != null)
                {
                    if (cert.Verify())
                    {
                        context.Response.StatusCode = 401;
                        reason = string.Format("SSL client certificate is not valid");
                    }
                    else if (cert.IssuerName.Name != _options.RequiredCertificateIssuer)
                    {
                        context.Response.StatusCode = 401;
                        reason = string.Format("SSL client certificate issued by a concrete issuer is required. Your issuer: {0}", cert.IssuerName.Name);
                    }
                }
                else
                {
                    if (_options.ClientCertificateValidator != null)
                    {
                        try
                        {
                            _options.ClientCertificateValidator.Validate(cert);
                        }
                        catch (Exception ex)
                        {
                            context.Response.StatusCode = 403;
                            context.Response.ReasonPhrase = ex.Message;

                            return;
                        }
                    }
                }
            }

            if (reason != null)
            {
                context.Response.ReasonPhrase = reason;
                context.Response.Write(context.Response.ReasonPhrase);
                return;
            }
            


            await _next(env);
        }
    }
}