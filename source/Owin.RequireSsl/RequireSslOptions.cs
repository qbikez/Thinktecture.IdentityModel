/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

namespace Thinktecture.IdentityModel.Owin
{
    public class RequireSslOptions
    {
        public bool RequireClientCertificate { get; set; }
        public bool AllowHttp { get; set; }
        public bool WriteReasonToContent { get; set; }
    }
}