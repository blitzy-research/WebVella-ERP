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
			// Security H-01: the AutoMapper pin was raised to [15.1.3]; the advisory and the licence
			// consequence are recorded at the pin itself in WebVella.Erp.csproj. From 15.x
			// MapperConfiguration REQUIRES an ILoggerFactory, which is the only reason this call changed:
			// a no-op factory is supplied here, the repository's only mapping-configuration construction
			// site. The platform performs no AutoMapper logging, so behaviour, Initialize's signature and
			// both of its call sites are unchanged.
			Mapper = new Mapper(new MapperConfiguration(cfg, NullLoggerFactory.Instance));
		}
	}
}
