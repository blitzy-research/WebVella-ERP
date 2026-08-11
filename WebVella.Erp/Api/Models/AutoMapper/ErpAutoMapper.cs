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
			// AutoMapper 15 requires an ILoggerFactory here; the platform performs no mapping logging,
			// so a no-op factory keeps behaviour identical to the pre-15 overload.
			Mapper = new Mapper(new MapperConfiguration(cfg, NullLoggerFactory.Instance));
		}
	}
}
