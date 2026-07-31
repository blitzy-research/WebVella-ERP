using AutoMapper;
using AutoMapper.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using System;
using System.Collections.Generic;
using System.Text;

namespace WebVella.Erp.Api.Models.AutoMapper
{
	public static class ErpAutoMapper
	{
		public static IMapper Mapper = null;

		public static void Initialize(MapperConfigurationExpression cfg)
		{
			// Security H-01 (CWE-674, OWASP A06): AutoMapper was pinned up to [15.1.3] to close the
			// uncontrolled-recursion denial of service GHSA-rvv3-g6hj-g44x / CVE-2026-32933. From 15.x the
			// MapperConfiguration constructor requires an ILoggerFactory, so one is supplied here. The
			// no-op factory keeps the previous behaviour exactly (AutoMapper emitted no logs before) and
			// leaves Initialize's signature - and therefore both of its call sites - unchanged.
			Mapper = new Mapper(new MapperConfiguration(cfg, NullLoggerFactory.Instance));
		}
	}
}
