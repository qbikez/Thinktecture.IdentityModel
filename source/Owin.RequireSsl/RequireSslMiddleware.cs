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

            var cert = context.Get<X509Certificate2>("ssl.ClientCertificate");
            if (cert == null)
            {
                var certHeader = context.Request.Headers["X-ARR-ClientCert"];
                if (!String.IsNullOrEmpty(certHeader))
                {
                    
                    try
                    {
                        byte[] clientCertBytes = Convert.FromBase64String(certHeader);
                        cert = new X509Certificate2(clientCertBytes);
                        _options.Log($"ssl client cert found in ARR header: {cert.SubjectName}");
                    }
                    catch (Exception ex)
                    {
                        _options.Log($"ssl error: failed to decode cert from ARR header: {ex.Message}");
                        context.Response.StatusCode = 403;
                        reason = ex.Message;
                    }                  
                }          
            }

            if (cert == null && _options.RequireClientCertificate)
            {
                _options.Log($"no client cert and no ARR header found");
                context.Response.StatusCode = 403;
                reason = "SSL client certificate is required.";
            }                
            else
            {
                if (_options.ClientCertificateValidator != null || _options.ValidateFunc != null)
                {
                    try
                    {
                        if (_options.ValidateFunc != null)
                            _options.ValidateFunc(cert);
                        if (_options.ClientCertificateValidator != null)
                            _options.ClientCertificateValidator.Validate(cert);
                    }
                    catch (Exception ex)
                    {
                        context.Response.StatusCode = 403;
                        reason = ex.Message;
                    }
                }
            }
            

            if (reason != null)
            {
                context.Response.ReasonPhrase = reason.Replace("\r\n", " ");
                if (_options.Log != null)
                {
                    _options.Log(string.Format("ssl error: {0} ({1})", context.Response.StatusCode, reason));
                }
                

                if (_options.WriteReasonToContent)
                    context.Response.Write(reason);
                return;
            }
            


            await _next(env);
        }
    }
}