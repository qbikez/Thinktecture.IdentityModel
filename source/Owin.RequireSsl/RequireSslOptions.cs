/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using System;
using System.IdentityModel.Selectors;
using System.Security.Cryptography.X509Certificates;

namespace Thinktecture.IdentityModel.Owin
{
    public class RequireSslOptions
    {
        public bool RequireClientCertificate { get; set; }
        public bool AllowHttp { get; set; }
        public bool WriteReasonToContent { get; set; }
        public X509CertificateValidator ClientCertificateValidator { get; set; }
        public Action<X509Certificate2> ValidateFunc { get; set; }

        public RequireSslOptions()
        {
            RequireClientCertificate = false;
            ClientCertificateValidator = X509CertificateValidator.None;
            ValidateFunc = null;
        }
    }
}