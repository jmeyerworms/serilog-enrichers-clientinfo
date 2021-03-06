﻿using Serilog.Core;
using Serilog.Events;
using System;
using System.Linq;

#if NETFULL

using Serilog.Enrichers.ClientInfo.Accessors;

#else
using Microsoft.AspNetCore.Http;
#endif

namespace Serilog.Enrichers
{
    public class ClientIpEnricher : ILogEventEnricher
    {
        private const string IpAddressPropertyName = "ClientIp";
        private readonly IHttpContextAccessor _contextAccessor;

        public ClientIpEnricher()
        {
            _contextAccessor = new HttpContextAccessor();
        }

        internal ClientIpEnricher(IHttpContextAccessor contextAccessor)
        {
            _contextAccessor = contextAccessor;
        }

        public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
        {
            if (_contextAccessor.HttpContext == null)
                return;

            var ipAddress = GetIpAddress();

            if (string.IsNullOrWhiteSpace(ipAddress))
                ipAddress = "unknown";

            ipAddress = TrunkatIPAddress(ipAddress);

            var ipAddressProperty = new LogEventProperty(IpAddressPropertyName, new ScalarValue(ipAddress));

            logEvent.AddPropertyIfAbsent(ipAddressProperty);
        }

#if NETFULL

        private string GetIpAddress()
        {
            var ipAddress = _contextAccessor.HttpContext.Request.ServerVariables["HTTP_X_FORWARDED_FOR"];

            if (!string.IsNullOrEmpty(ipAddress))
            {
                return GetIpAddressFromProxy(ipAddress);
            }

            return _contextAccessor.HttpContext.Request.ServerVariables["REMOTE_ADDR"];
        }

#else
     private string GetIpAddress()
     {
         var ipAddress = _contextAccessor.HttpContext.Request.Headers["X-forwarded-for"].FirstOrDefault();

         if (!string.IsNullOrEmpty(ipAddress))
         {
             return GetIpAddressFromProxy(ipAddress);
         }
         
         return _contextAccessor.HttpContext.Connection.RemoteIpAddress.ToString();
     }
#endif

        private string GetIpAddressFromProxy(string proxiedIpList)
        {
            var addresses = proxiedIpList.Split(',');

            if (addresses.Length != 0)
            {
                // If IP contains port, it will be after the last : (IPv6 uses : as delimiter and could have more of them)
                return addresses[0].Contains(":")
                    ? addresses[0].Substring(0, addresses[0].LastIndexOf(":", StringComparison.Ordinal))
                    : addresses[0];
            }

            return string.Empty;
        }

        private string TrunkatIPAddress(string ipaddress)
        {
            return ipaddress.Substring(0, ipaddress.LastIndexOf(".", StringComparison.Ordinal));
        }

    }
}
