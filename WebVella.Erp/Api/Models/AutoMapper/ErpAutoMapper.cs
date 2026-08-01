using System;
using System.Collections.Generic;
using System.Text;
using AutoMapper;
using AutoMapper.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace WebVella.Erp.Api.Models.AutoMapper
{
	public static class ErpAutoMapper
	{
		public static IMapper Mapper = null;

		public static void Initialize(MapperConfigurationExpression cfg)
		{
			// Security H-01 (CWE-674 uncontrolled recursion, OWASP A06:2021 Vulnerable and Outdated
			// Components): AutoMapper below 15.1.1 allows denial of service through uncontrolled
			// recursion (GHSA-rvv3-g6hj-g44x / CVE-2026-32933); the pin was raised to [15.1.3] in
			// WebVella.Erp.csproj. From 15.x the MapperConfiguration constructor requires an
			// ILoggerFactory, so a no-op factory is supplied here, at the repository's only
			// mapping-configuration construction site. The platform performs no AutoMapper logging, so
			// behaviour, Initialize's signature and both of its call sites are all unchanged.
			Mapper = new Mapper(new MapperConfiguration(cfg, NullLoggerFactory.Instance));
		}
	}
}
