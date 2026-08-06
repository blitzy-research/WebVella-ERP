using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Formatters.Binary;
using WebVella.Erp.Api;
using WebVella.Erp.Api.Models;
using WebVella.Erp.Api.Models.AutoMapper;

namespace WebVella.Erp.Utilities
{
	public class Helpers
	{
		public static List<Currency> GetAllCurrency()
		{
			var result = new List<Currency>();
			var currencyJson = "";
			#region << Currency List as String >>
			currencyJson = @"{
  ""aed"": {
  	""priority"": 100,
    ""iso_code"": ""AED"",
    ""name"": ""United Arab Emirates Dirham"",
    ""symbol"": ""د.إ"",
    ""alternate_symbols"": [""DH"", ""Dhs""],
    ""subunit"": ""Fils"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""784"",
    ""smallest_denomination"": 25
  },
  ""afn"": {
    ""priority"": 100,
    ""iso_code"": ""AFN"",
    ""name"": ""Afghan Afghani"",
    ""symbol"": ""؋"",
    ""alternate_symbols"": [""Af"", ""Afs""],
    ""subunit"": ""Pul"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""971"",
    ""smallest_denomination"": 100
  },
  ""all"": {
    ""priority"": 100,
    ""iso_code"": ""ALL"",
    ""name"": ""Albanian Lek"",
    ""symbol"": ""L"",
    ""disambiguate_symbol"": ""Lek"",
    ""alternate_symbols"": [""Lek""],
    ""subunit"": ""Qintar"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""008"",
    ""smallest_denomination"": 100
  },
  ""amd"": {
    ""priority"": 100,
    ""iso_code"": ""AMD"",
    ""name"": ""Armenian Dram"",
    ""symbol"": ""դր."",
    ""alternate_symbols"": [""dram""],
    ""subunit"": ""Luma"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""051"",
    ""smallest_denomination"": 10
  },
  ""ang"": {
    ""priority"": 100,
    ""iso_code"": ""ANG"",
    ""name"": ""Netherlands Antillean Gulden"",
    ""symbol"": ""ƒ"",
    ""alternate_symbols"": [""NAƒ"", ""NAf"", ""f""],
    ""subunit"": ""Cent"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""&#x0192;"",
    ""decimal_mark"": "","",
    ""thousands_separator"": ""."",
    ""iso_numeric"": ""532"",
    ""smallest_denomination"": 1
  },
  ""aoa"": {
    ""priority"": 100,
    ""iso_code"": ""AOA"",
    ""name"": ""Angolan Kwanza"",
    ""symbol"": ""Kz"",
    ""alternate_symbols"": [],
    ""subunit"": ""Cêntimo"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""973"",
    ""smallest_denomination"": 10
  },
  ""ars"": {
    ""priority"": 100,
    ""iso_code"": ""ARS"",
    ""name"": ""Argentine Peso"",
    ""symbol"": ""$"",
    ""disambiguate_symbol"": ""$m/n"",
    ""alternate_symbols"": [""$m/n"", ""m$n""],
    ""subunit"": ""Centavo"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""&#x20B1;"",
    ""decimal_mark"": "","",
    ""thousands_separator"": ""."",
    ""iso_numeric"": ""032"",
    ""smallest_denomination"": 1
  },
  ""aud"": {
    ""priority"": 4,
    ""iso_code"": ""AUD"",
    ""name"": ""Australian Dollar"",
    ""symbol"": ""$"",
    ""disambiguate_symbol"": ""A$"",
    ""alternate_symbols"": [""A$""],
    ""subunit"": ""Cent"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""$"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""036"",
    ""smallest_denomination"": 5
  },
  ""awg"": {
    ""priority"": 100,
    ""iso_code"": ""AWG"",
    ""name"": ""Aruban Florin"",
    ""symbol"": ""ƒ"",
    ""alternate_symbols"": [""Afl""],
    ""subunit"": ""Cent"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": ""&#x0192;"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""533"",
    ""smallest_denomination"": 5
  },
  ""azn"": {
    ""priority"": 100,
    ""iso_code"": ""AZN"",
    ""name"": ""Azerbaijani Manat"",
    ""symbol"": ""₼"",
    ""alternate_symbols"": [""m"", ""man""],
    ""subunit"": ""Qəpik"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""944"",
    ""smallest_denomination"": 1
  },
  ""bam"": {
    ""priority"": 100,
    ""iso_code"": ""BAM"",
    ""name"": ""Bosnia and Herzegovina Convertible Mark"",
    ""symbol"": ""КМ"",
    ""alternate_symbols"": [""KM""],
    ""subunit"": ""Fening"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""977"",
    ""smallest_denomination"": 5
  },
  ""bbd"": {
    ""priority"": 100,
    ""iso_code"": ""BBD"",
    ""name"": ""Barbadian Dollar"",
    ""symbol"": ""$"",
    ""disambiguate_symbol"": ""Bds$"",
    ""alternate_symbols"": [""Bds$""],
    ""subunit"": ""Cent"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": ""$"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""052"",
    ""smallest_denomination"": 1
  },
  ""bdt"": {
    ""priority"": 100,
    ""iso_code"": ""BDT"",
    ""name"": ""Bangladeshi Taka"",
    ""symbol"": ""৳"",
    ""alternate_symbols"": [""Tk""],
    ""subunit"": ""Paisa"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""050"",
    ""smallest_denomination"": 1
  },
  ""bgn"": {
    ""priority"": 100,
    ""iso_code"": ""BGN"",
    ""name"": ""Bulgarian Lev"",
    ""symbol"": ""лв."",
    ""alternate_symbols"": [""lev"", ""leva"", ""лев"", ""лева""],
    ""subunit"": ""Stotinka"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""975"",
    ""smallest_denomination"": 1
  },
  ""bhd"": {
    ""priority"": 100,
    ""iso_code"": ""BHD"",
    ""name"": ""Bahraini Dinar"",
    ""symbol"": ""ب.د"",
    ""alternate_symbols"": [""BD""],
    ""subunit"": ""Fils"",
    ""subunit_to_unit"": 1000,
    ""symbol_first"": true,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""048"",
    ""smallest_denomination"": 5
  },
  ""bif"": {
    ""priority"": 100,
    ""iso_code"": ""BIF"",
    ""name"": ""Burundian Franc"",
    ""symbol"": ""Fr"",
    ""disambiguate_symbol"": ""FBu"",
    ""alternate_symbols"": [""FBu""],
    ""subunit"": ""Centime"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""108"",
    ""smallest_denomination"": 100
  },
  ""bmd"": {
    ""priority"": 100,
    ""iso_code"": ""BMD"",
    ""name"": ""Bermudian Dollar"",
    ""symbol"": ""$"",
    ""disambiguate_symbol"": ""BD$"",
    ""alternate_symbols"": [""BD$""],
    ""subunit"": ""Cent"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""$"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""060"",
    ""smallest_denomination"": 1
  },
  ""bnd"": {
    ""priority"": 100,
    ""iso_code"": ""BND"",
    ""name"": ""Brunei Dollar"",
    ""symbol"": ""$"",
    ""disambiguate_symbol"": ""BND"",
    ""alternate_symbols"": [""B$""],
    ""subunit"": ""Sen"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""$"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""096"",
    ""smallest_denomination"": 1
  },
  ""bob"": {
    ""priority"": 100,
    ""iso_code"": ""BOB"",
    ""name"": ""Bolivian Boliviano"",
    ""symbol"": ""Bs."",
    ""alternate_symbols"": [""Bs""],
    ""subunit"": ""Centavo"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""068"",
    ""smallest_denomination"": 10
  },
  ""brl"": {
    ""priority"": 100,
    ""iso_code"": ""BRL"",
    ""name"": ""Brazilian Real"",
    ""symbol"": ""R$"",
    ""subunit"": ""Centavo"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""R$"",
    ""decimal_mark"": "","",
    ""thousands_separator"": ""."",
    ""iso_numeric"": ""986"",
    ""smallest_denomination"": 5
  },
  ""bsd"": {
    ""priority"": 100,
    ""iso_code"": ""BSD"",
    ""name"": ""Bahamian Dollar"",
    ""symbol"": ""$"",
    ""disambiguate_symbol"": ""BSD"",
    ""alternate_symbols"": [""B$""],
    ""subunit"": ""Cent"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""$"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""044"",
    ""smallest_denomination"": 1
  },
  ""btn"": {
    ""priority"": 100,
    ""iso_code"": ""BTN"",
    ""name"": ""Bhutanese Ngultrum"",
    ""symbol"": ""Nu."",
    ""alternate_symbols"": [""Nu""],
    ""subunit"": ""Chertrum"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""064"",
    ""smallest_denomination"": 5
  },
  ""bwp"": {
    ""priority"": 100,
    ""iso_code"": ""BWP"",
    ""name"": ""Botswana Pula"",
    ""symbol"": ""P"",
    ""alternate_symbols"": [],
    ""subunit"": ""Thebe"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""072"",
    ""smallest_denomination"": 5
  },
  ""byn"": {
    ""priority"": 100,
    ""iso_code"": ""BYN"",
    ""name"": ""Belarusian Ruble"",
    ""symbol"": ""Br"",
    ""disambiguate_symbol"": ""BYN"",
    ""alternate_symbols"": [""бел. руб."", ""б.р."", ""руб."", ""р.""],
    ""subunit"": ""Kapeyka"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": "","",
    ""thousands_separator"": "" "",
    ""iso_numeric"": ""933"",
    ""smallest_denomination"": 1
  },
  ""byr"": {
    ""priority"": 50,
    ""iso_code"": ""BYR"",
    ""name"": ""Belarusian Ruble"",
    ""symbol"": ""Br"",
    ""disambiguate_symbol"": ""BYR"",
    ""alternate_symbols"": [""бел. руб."", ""б.р."", ""руб."", ""р.""],
    ""subunit"": null,
    ""subunit_to_unit"": 1,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": "","",
    ""thousands_separator"": "" "",
    ""iso_numeric"": ""974"",
    ""smallest_denomination"": 100
  },
  ""bzd"": {
    ""priority"": 100,
    ""iso_code"": ""BZD"",
    ""name"": ""Belize Dollar"",
    ""symbol"": ""$"",
    ""disambiguate_symbol"": ""BZ$"",
    ""alternate_symbols"": [""BZ$""],
    ""subunit"": ""Cent"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""$"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""084"",
    ""smallest_denomination"": 1
  },
  ""cad"": {
    ""priority"": 5,
    ""iso_code"": ""CAD"",
    ""name"": ""Canadian Dollar"",
    ""symbol"": ""$"",
    ""disambiguate_symbol"": ""C$"",
    ""alternate_symbols"": [""C$"", ""CAD$""],
    ""subunit"": ""Cent"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""$"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""124"",
    ""smallest_denomination"": 5
  },
  ""cdf"": {
    ""priority"": 100,
    ""iso_code"": ""CDF"",
    ""name"": ""Congolese Franc"",
    ""symbol"": ""Fr"",
    ""disambiguate_symbol"": ""FC"",
    ""alternate_symbols"": [""FC""],
    ""subunit"": ""Centime"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""976"",
    ""smallest_denomination"": 1
  },
  ""chf"": {
    ""priority"": 100,
    ""iso_code"": ""CHF"",
    ""name"": ""Swiss Franc"",
    ""symbol"": ""CHF"",
    ""alternate_symbols"": [""SFr"", ""Fr""],
    ""subunit"": ""Rappen"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""756"",
    ""smallest_denomination"": 5
  },
  ""clf"": {
    ""priority"": 100,
    ""iso_code"": ""CLF"",
    ""name"": ""Unidad de Fomento"",
    ""symbol"": ""UF"",
    ""alternate_symbols"": [],
    ""subunit"": ""Peso"",
    ""subunit_to_unit"": 10000,
    ""symbol_first"": true,
    ""html_entity"": ""&#x20B1;"",
    ""decimal_mark"": "","",
    ""thousands_separator"": ""."",
    ""iso_numeric"": ""990""
  },
  ""clp"": {
    ""priority"": 100,
    ""iso_code"": ""CLP"",
    ""name"": ""Chilean Peso"",
    ""symbol"": ""$"",
    ""disambiguate_symbol"": ""CLP"",
    ""alternate_symbols"": [],
    ""subunit"": ""Peso"",
    ""subunit_to_unit"": 1,
    ""symbol_first"": true,
    ""html_entity"": ""&#36;"",
    ""decimal_mark"": "","",
    ""thousands_separator"": ""."",
    ""iso_numeric"": ""152"",
    ""smallest_denomination"": 1
  },
  ""cny"": {
    ""priority"": 100,
    ""iso_code"": ""CNY"",
    ""name"": ""Chinese Renminbi Yuan"",
    ""symbol"": ""¥"",
    ""alternate_symbols"": [""CN¥"", ""元"", ""CN元""],
    ""subunit"": ""Fen"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""￥"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""156"",
    ""smallest_denomination"": 1
  },
  ""cop"": {
    ""priority"": 100,
    ""iso_code"": ""COP"",
    ""name"": ""Colombian Peso"",
    ""symbol"": ""$"",
    ""disambiguate_symbol"": ""COL$"",
    ""alternate_symbols"": [""COL$""],
    ""subunit"": ""Centavo"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""&#x20B1;"",
    ""decimal_mark"": "","",
    ""thousands_separator"": ""."",
    ""iso_numeric"": ""170"",
    ""smallest_denomination"": 20
  },
  ""crc"": {
    ""priority"": 100,
    ""iso_code"": ""CRC"",
    ""name"": ""Costa Rican Colón"",
    ""symbol"": ""₡"",
    ""alternate_symbols"": [""¢""],
    ""subunit"": ""Céntimo"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""&#x20A1;"",
    ""decimal_mark"": "","",
    ""thousands_separator"": ""."",
    ""iso_numeric"": ""188"",
    ""smallest_denomination"": 500
  },
  ""cuc"": {
    ""priority"": 100,
    ""iso_code"": ""CUC"",
    ""name"": ""Cuban Convertible Peso"",
    ""symbol"": ""$"",
    ""disambiguate_symbol"": ""CUC$"",
    ""alternate_symbols"": [""CUC$""],
    ""subunit"": ""Centavo"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""931"",
    ""smallest_denomination"": 1
  },
  ""cup"": {
    ""priority"": 100,
    ""iso_code"": ""CUP"",
    ""name"": ""Cuban Peso"",
    ""symbol"": ""$"",
    ""disambiguate_symbol"": ""$MN"",
    ""alternate_symbols"": [""$MN""],
    ""subunit"": ""Centavo"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""&#x20B1;"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""192"",
    ""smallest_denomination"": 1
  },
  ""cve"": {
    ""priority"": 100,
    ""iso_code"": ""CVE"",
    ""name"": ""Cape Verdean Escudo"",
    ""symbol"": ""$"",
    ""disambiguate_symbol"": ""Esc"",
    ""alternate_symbols"": [""Esc""],
    ""subunit"": ""Centavo"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""132"",
    ""smallest_denomination"": 100
  },
  ""czk"": {
    ""priority"": 100,
    ""iso_code"": ""CZK"",
    ""name"": ""Czech Koruna"",
    ""symbol"": ""Kč"",
    ""alternate_symbols"": [],
    ""subunit"": ""Haléř"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": "","",
    ""thousands_separator"": ""."",
    ""iso_numeric"": ""203"",
    ""smallest_denomination"": 100
  },
  ""djf"": {
    ""priority"": 100,
    ""iso_code"": ""DJF"",
    ""name"": ""Djiboutian Franc"",
    ""symbol"": ""Fdj"",
    ""alternate_symbols"": [],
    ""subunit"": ""Centime"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""262"",
    ""smallest_denomination"": 100
  },
  ""dkk"": {
    ""priority"": 100,
    ""iso_code"": ""DKK"",
    ""name"": ""Danish Krone"",
    ""symbol"": ""kr."",
    ""disambiguate_symbol"": ""DKK"",
    ""alternate_symbols"": ["",-""],
    ""subunit"": ""Øre"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": "","",
    ""thousands_separator"": ""."",
    ""iso_numeric"": ""208"",
    ""smallest_denomination"": 50
  },
  ""dop"": {
    ""priority"": 100,
    ""iso_code"": ""DOP"",
    ""name"": ""Dominican Peso"",
    ""symbol"": ""$"",
    ""disambiguate_symbol"": ""RD$"",
    ""alternate_symbols"": [""RD$""],
    ""subunit"": ""Centavo"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""&#x20B1;"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""214"",
    ""smallest_denomination"": 100
  },
  ""dzd"": {
    ""priority"": 100,
    ""iso_code"": ""DZD"",
    ""name"": ""Algerian Dinar"",
    ""symbol"": ""د.ج"",
    ""alternate_symbols"": [""DA""],
    ""subunit"": ""Centime"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""012"",
    ""smallest_denomination"": 100
  },
  ""egp"": {
    ""priority"": 100,
    ""iso_code"": ""EGP"",
    ""name"": ""Egyptian Pound"",
    ""symbol"": ""ج.م"",
    ""alternate_symbols"": [""LE"", ""E£"", ""L.E.""],
    ""subunit"": ""Piastre"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""&#x00A3;"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""818"",
    ""smallest_denomination"": 25
  },
  ""ern"": {
    ""priority"": 100,
    ""iso_code"": ""ERN"",
    ""name"": ""Eritrean Nakfa"",
    ""symbol"": ""Nfk"",
    ""alternate_symbols"": [],
    ""subunit"": ""Cent"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""232"",
    ""smallest_denomination"": 1
  },
  ""etb"": {
    ""priority"": 100,
    ""iso_code"": ""ETB"",
    ""name"": ""Ethiopian Birr"",
    ""symbol"": ""Br"",
    ""disambiguate_symbol"": ""ETB"",
    ""alternate_symbols"": [],
    ""subunit"": ""Santim"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""230"",
    ""smallest_denomination"": 1
  },
  ""eur"": {
    ""priority"": 2,
    ""iso_code"": ""EUR"",
    ""name"": ""Euro"",
    ""symbol"": ""€"",
    ""alternate_symbols"": [],
    ""subunit"": ""Cent"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""&#x20AC;"",
    ""decimal_mark"": "","",
    ""thousands_separator"": ""."",
    ""iso_numeric"": ""978"",
    ""smallest_denomination"": 1
  },
  ""fjd"": {
    ""priority"": 100,
    ""iso_code"": ""FJD"",
    ""name"": ""Fijian Dollar"",
    ""symbol"": ""$"",
    ""disambiguate_symbol"": ""FJ$"",
    ""alternate_symbols"": [""FJ$""],
    ""subunit"": ""Cent"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": ""$"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""242"",
    ""smallest_denomination"": 5
  },
  ""fkp"": {
    ""priority"": 100,
    ""iso_code"": ""FKP"",
    ""name"": ""Falkland Pound"",
    ""symbol"": ""£"",
    ""disambiguate_symbol"": ""FK£"",
    ""alternate_symbols"": [""FK£""],
    ""subunit"": ""Penny"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": ""&#x00A3;"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""238"",
    ""smallest_denomination"": 1
  },
  ""gbp"": {
    ""priority"": 3,
    ""iso_code"": ""GBP"",
    ""name"": ""British Pound"",
    ""symbol"": ""£"",
    ""alternate_symbols"": [],
    ""subunit"": ""Penny"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""&#x00A3;"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""826"",
    ""smallest_denomination"": 1
  },
  ""gel"": {
    ""priority"": 100,
    ""iso_code"": ""GEL"",
    ""name"": ""Georgian Lari"",
    ""symbol"": ""ლ"",
    ""alternate_symbols"": [""lari""],
    ""subunit"": ""Tetri"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""981"",
    ""smallest_denomination"": 1
  },
  ""ghs"": {
    ""priority"": 100,
    ""iso_code"": ""GHS"",
    ""name"": ""Ghanaian Cedi"",
    ""symbol"": ""₵"",
    ""alternate_symbols"": [""GH¢"", ""GH₵""],
    ""subunit"": ""Pesewa"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""&#x20B5;"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""936"",
    ""smallest_denomination"": 1
  },
  ""gip"": {
    ""priority"": 100,
    ""iso_code"": ""GIP"",
    ""name"": ""Gibraltar Pound"",
    ""symbol"": ""£"",
    ""disambiguate_symbol"": ""GIP"",
    ""alternate_symbols"": [],
    ""subunit"": ""Penny"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""&#x00A3;"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""292"",
    ""smallest_denomination"": 1
  },
  ""gmd"": {
    ""priority"": 100,
    ""iso_code"": ""GMD"",
    ""name"": ""Gambian Dalasi"",
    ""symbol"": ""D"",
    ""alternate_symbols"": [],
    ""subunit"": ""Butut"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""270"",
    ""smallest_denomination"": 1
  },
  ""gnf"": {
    ""priority"": 100,
    ""iso_code"": ""GNF"",
    ""name"": ""Guinean Franc"",
    ""symbol"": ""Fr"",
    ""disambiguate_symbol"": ""FG"",
    ""alternate_symbols"": [""FG"", ""GFr""],
    ""subunit"": ""Centime"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""324"",
    ""smallest_denomination"": 100
  },
  ""gtq"": {
    ""priority"": 100,
    ""iso_code"": ""GTQ"",
    ""name"": ""Guatemalan Quetzal"",
    ""symbol"": ""Q"",
    ""alternate_symbols"": [],
    ""subunit"": ""Centavo"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""320"",
    ""smallest_denomination"": 1
  },
  ""gyd"": {
    ""priority"": 100,
    ""iso_code"": ""GYD"",
    ""name"": ""Guyanese Dollar"",
    ""symbol"": ""$"",
    ""disambiguate_symbol"": ""G$"",
    ""alternate_symbols"": [""G$""],
    ""subunit"": ""Cent"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": ""$"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""328"",
    ""smallest_denomination"": 100
  },
  ""hkd"": {
    ""priority"": 100,
    ""iso_code"": ""HKD"",
    ""name"": ""Hong Kong Dollar"",
    ""symbol"": ""$"",
    ""disambiguate_symbol"": ""HK$"",
    ""alternate_symbols"": [""HK$""],
    ""subunit"": ""Cent"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""$"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""344"",
    ""smallest_denomination"": 10
  },
  ""hnl"": {
    ""priority"": 100,
    ""iso_code"": ""HNL"",
    ""name"": ""Honduran Lempira"",
    ""symbol"": ""L"",
    ""disambiguate_symbol"": ""HNL"",
    ""alternate_symbols"": [],
    ""subunit"": ""Centavo"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""340"",
    ""smallest_denomination"": 5
  },
  ""hrk"": {
    ""priority"": 100,
    ""iso_code"": ""HRK"",
    ""name"": ""Croatian Kuna"",
    ""symbol"": ""kn"",
    ""alternate_symbols"": [],
    ""subunit"": ""Lipa"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": "","",
    ""thousands_separator"": ""."",
    ""iso_numeric"": ""191"",
    ""smallest_denomination"": 1
  },
  ""htg"": {
    ""priority"": 100,
    ""iso_code"": ""HTG"",
    ""name"": ""Haitian Gourde"",
    ""symbol"": ""G"",
    ""alternate_symbols"": [],
    ""subunit"": ""Centime"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""332"",
    ""smallest_denomination"": 5
  },
  ""huf"": {
    ""priority"": 100,
    ""iso_code"": ""HUF"",
    ""name"": ""Hungarian Forint"",
    ""symbol"": ""Ft"",
    ""alternate_symbols"": [],
    ""subunit"": ""Fillér"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": "","",
    ""thousands_separator"": ""."",
    ""iso_numeric"": ""348"",
    ""smallest_denomination"": 500
  },
  ""idr"": {
    ""priority"": 100,
    ""iso_code"": ""IDR"",
    ""name"": ""Indonesian Rupiah"",
    ""symbol"": ""Rp"",
    ""alternate_symbols"": [],
    ""subunit"": ""Sen"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": """",
    ""decimal_mark"": "","",
    ""thousands_separator"": ""."",
    ""iso_numeric"": ""360"",
    ""smallest_denomination"": 5000
  },
  ""ils"": {
    ""priority"": 100,
    ""iso_code"": ""ILS"",
    ""name"": ""Israeli New Sheqel"",
    ""symbol"": ""₪"",
    ""alternate_symbols"": [""ש״ח"", ""NIS""],
    ""subunit"": ""Agora"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""&#x20AA;"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""376"",
    ""smallest_denomination"": 10
  },
  ""inr"": {
    ""priority"": 100,
    ""iso_code"": ""INR"",
    ""name"": ""Indian Rupee"",
    ""symbol"": ""₹"",
    ""alternate_symbols"": [""Rs"", ""৳"", ""૱"", ""௹"", ""रु"", ""₨""],
    ""subunit"": ""Paisa"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""&#x20b9;"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""356"",
    ""smallest_denomination"": 50
  },
  ""iqd"": {
    ""priority"": 100,
    ""iso_code"": ""IQD"",
    ""name"": ""Iraqi Dinar"",
    ""symbol"": ""ع.د"",
    ""alternate_symbols"": [],
    ""subunit"": ""Fils"",
    ""subunit_to_unit"": 1000,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""368"",
    ""smallest_denomination"": 50000
  },
  ""irr"": {
    ""priority"": 100,
    ""iso_code"": ""IRR"",
    ""name"": ""Iranian Rial"",
    ""symbol"": ""﷼"",
    ""alternate_symbols"": [],
    ""subunit"": null,
    ""subunit_to_unit"": 1,
    ""symbol_first"": true,
    ""html_entity"": ""&#xFDFC;"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""364"",
    ""smallest_denomination"": 5000
  },
  ""isk"": {
    ""priority"": 100,
    ""iso_code"": ""ISK"",
    ""name"": ""Icelandic Króna"",
    ""symbol"": ""kr"",
    ""alternate_symbols"": [""Íkr""],
    ""subunit"": null,
    ""subunit_to_unit"": 1,
    ""symbol_first"": true,
    ""html_entity"": """",
    ""decimal_mark"": "","",
    ""thousands_separator"": ""."",
    ""iso_numeric"": ""352"",
    ""smallest_denomination"": 1
  },
  ""jmd"": {
    ""priority"": 100,
    ""iso_code"": ""JMD"",
    ""name"": ""Jamaican Dollar"",
    ""symbol"": ""$"",
    ""disambiguate_symbol"": ""J$"",
    ""alternate_symbols"": [""J$""],
    ""subunit"": ""Cent"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""$"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""388"",
    ""smallest_denomination"": 1
  },
  ""jod"": {
    ""priority"": 100,
    ""iso_code"": ""JOD"",
    ""name"": ""Jordanian Dinar"",
    ""symbol"": ""د.ا"",
    ""alternate_symbols"": [""JD""],
    ""subunit"": ""Fils"",
    ""subunit_to_unit"": 1000,
    ""symbol_first"": true,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""400"",
    ""smallest_denomination"": 5
  },
  ""jpy"": {
    ""priority"": 6,
    ""iso_code"": ""JPY"",
    ""name"": ""Japanese Yen"",
    ""symbol"": ""¥"",
    ""alternate_symbols"": [""円"", ""圓""],
    ""subunit"": null,
    ""subunit_to_unit"": 1,
    ""symbol_first"": true,
    ""html_entity"": ""&#x00A5;"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""392"",
    ""smallest_denomination"": 1
  },
  ""kes"": {
    ""priority"": 100,
    ""iso_code"": ""KES"",
    ""name"": ""Kenyan Shilling"",
    ""symbol"": ""KSh"",
    ""alternate_symbols"": [""Sh""],
    ""subunit"": ""Cent"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""404"",
    ""smallest_denomination"": 50
  },
  ""kgs"": {
    ""priority"": 100,
    ""iso_code"": ""KGS"",
    ""name"": ""Kyrgyzstani Som"",
    ""symbol"": ""som"",
    ""alternate_symbols"": [""сом""],
    ""subunit"": ""Tyiyn"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""417"",
    ""smallest_denomination"": 1
  },
  ""khr"": {
    ""priority"": 100,
    ""iso_code"": ""KHR"",
    ""name"": ""Cambodian Riel"",
    ""symbol"": ""៛"",
    ""alternate_symbols"": [],
    ""subunit"": ""Sen"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": ""&#x17DB;"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""116"",
    ""smallest_denomination"": 5000
  },
  ""kmf"": {
    ""priority"": 100,
    ""iso_code"": ""KMF"",
    ""name"": ""Comorian Franc"",
    ""symbol"": ""Fr"",
    ""disambiguate_symbol"": ""CF"",
    ""alternate_symbols"": [""CF""],
    ""subunit"": ""Centime"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""174"",
    ""smallest_denomination"": 100
  },
  ""kpw"": {
    ""priority"": 100,
    ""iso_code"": ""KPW"",
    ""name"": ""North Korean Won"",
    ""symbol"": ""₩"",
    ""alternate_symbols"": [],
    ""subunit"": ""Chŏn"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": ""&#x20A9;"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""408"",
    ""smallest_denomination"": 1
  },
  ""krw"": {
    ""priority"": 100,
    ""iso_code"": ""KRW"",
    ""name"": ""South Korean Won"",
    ""symbol"": ""₩"",
    ""subunit"": null,
    ""subunit_to_unit"": 1,
    ""alternate_symbols"": [],
    ""symbol_first"": true,
    ""html_entity"": ""&#x20A9;"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""410"",
    ""smallest_denomination"": 1
  },
  ""kwd"": {
    ""priority"": 100,
    ""iso_code"": ""KWD"",
    ""name"": ""Kuwaiti Dinar"",
    ""symbol"": ""د.ك"",
    ""alternate_symbols"": [""K.D.""],
    ""subunit"": ""Fils"",
    ""subunit_to_unit"": 1000,
    ""symbol_first"": true,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""414"",
    ""smallest_denomination"": 5
  },
  ""kyd"": {
    ""priority"": 100,
    ""iso_code"": ""KYD"",
    ""name"": ""Cayman Islands Dollar"",
    ""symbol"": ""$"",
    ""disambiguate_symbol"": ""CI$"",
    ""alternate_symbols"": [""CI$""],
    ""subunit"": ""Cent"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""$"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""136"",
    ""smallest_denomination"": 1
  },
  ""kzt"": {
    ""priority"": 100,
    ""iso_code"": ""KZT"",
    ""name"": ""Kazakhstani Tenge"",
    ""symbol"": ""〒"",
    ""alternate_symbols"": [],
    ""subunit"": ""Tiyn"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""398"",
    ""smallest_denomination"": 100
  },
  ""lak"": {
    ""priority"": 100,
    ""iso_code"": ""LAK"",
    ""name"": ""Lao Kip"",
    ""symbol"": ""₭"",
    ""alternate_symbols"": [""₭N""],
    ""subunit"": ""Att"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": ""&#x20AD;"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""418"",
    ""smallest_denomination"": 10
  },
  ""lbp"": {
    ""priority"": 100,
    ""iso_code"": ""LBP"",
    ""name"": ""Lebanese Pound"",
    ""symbol"": ""ل.ل"",
    ""alternate_symbols"": [""£"", ""L£""],
    ""subunit"": ""Piastre"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""&#x00A3;"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""422"",
    ""smallest_denomination"": 25000
  },
  ""lkr"": {
    ""priority"": 100,
    ""iso_code"": ""LKR"",
    ""name"": ""Sri Lankan Rupee"",
    ""symbol"": ""₨"",
    ""disambiguate_symbol"": ""SLRs"",
    ""alternate_symbols"": [""රු"", ""ரூ"", ""SLRs"", ""/-""],
    ""subunit"": ""Cent"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": ""&#x0BF9;"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""144"",
    ""smallest_denomination"": 100
  },
  ""lrd"": {
    ""priority"": 100,
    ""iso_code"": ""LRD"",
    ""name"": ""Liberian Dollar"",
    ""symbol"": ""$"",
    ""disambiguate_symbol"": ""L$"",
    ""alternate_symbols"": [""L$""],
    ""subunit"": ""Cent"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": ""$"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""430"",
    ""smallest_denomination"": 5
  },
  ""lsl"": {
    ""priority"": 100,
    ""iso_code"": ""LSL"",
    ""name"": ""Lesotho Loti"",
    ""symbol"": ""L"",
    ""disambiguate_symbol"": ""M"",
    ""alternate_symbols"": [""M""],
    ""subunit"": ""Sente"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""426"",
    ""smallest_denomination"": 1
  },
  ""ltl"": {
    ""priority"": 100,
    ""iso_code"": ""LTL"",
    ""name"": ""Lithuanian Litas"",
    ""symbol"": ""Lt"",
    ""alternate_symbols"": [],
    ""subunit"": ""Centas"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""440"",
    ""smallest_denomination"": 1
  },
  ""lvl"": {
    ""priority"": 100,
    ""iso_code"": ""LVL"",
    ""name"": ""Latvian Lats"",
    ""symbol"": ""Ls"",
    ""alternate_symbols"": [],
    ""subunit"": ""Santīms"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""428"",
    ""smallest_denomination"": 1
  },
  ""lyd"": {
    ""priority"": 100,
    ""iso_code"": ""LYD"",
    ""name"": ""Libyan Dinar"",
    ""symbol"": ""ل.د"",
    ""alternate_symbols"": [""LD""],
    ""subunit"": ""Dirham"",
    ""subunit_to_unit"": 1000,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""434"",
    ""smallest_denomination"": 50
  },
  ""mad"": {
    ""priority"": 100,
    ""iso_code"": ""MAD"",
    ""name"": ""Moroccan Dirham"",
    ""symbol"": ""د.م."",
    ""alternate_symbols"": [],
    ""subunit"": ""Centime"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""504"",
    ""smallest_denomination"": 1
  },
  ""mdl"": {
    ""priority"": 100,
    ""iso_code"": ""MDL"",
    ""name"": ""Moldovan Leu"",
    ""symbol"": ""L"",
    ""alternate_symbols"": [""lei""],
    ""subunit"": ""Ban"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""498"",
    ""smallest_denomination"": 1
  },
  ""mga"": {
    ""priority"": 100,
    ""iso_code"": ""MGA"",
    ""name"": ""Malagasy Ariary"",
    ""symbol"": ""Ar"",
    ""alternate_symbols"": [],
    ""subunit"": ""Iraimbilanja"",
    ""subunit_to_unit"": 5,
    ""symbol_first"": true,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""969"",
    ""smallest_denomination"": 1
  },
  ""mkd"": {
    ""priority"": 100,
    ""iso_code"": ""MKD"",
    ""name"": ""Macedonian Denar"",
    ""symbol"": ""ден"",
    ""alternate_symbols"": [],
    ""subunit"": ""Deni"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""807"",
    ""smallest_denomination"": 100
  },
  ""mmk"": {
    ""priority"": 100,
    ""iso_code"": ""MMK"",
    ""name"": ""Myanmar Kyat"",
    ""symbol"": ""K"",
    ""disambiguate_symbol"": ""MMK"",
    ""alternate_symbols"": [],
    ""subunit"": ""Pya"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""104"",
    ""smallest_denomination"": 50
  },
  ""mnt"": {
    ""priority"": 100,
    ""iso_code"": ""MNT"",
    ""name"": ""Mongolian Tögrög"",
    ""symbol"": ""₮"",
    ""alternate_symbols"": [],
    ""subunit"": ""Möngö"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": ""&#x20AE;"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""496"",
    ""smallest_denomination"": 2000
  },
  ""mop"": {
    ""priority"": 100,
    ""iso_code"": ""MOP"",
    ""name"": ""Macanese Pataca"",
    ""symbol"": ""P"",
    ""alternate_symbols"": [""MOP$""],
    ""subunit"": ""Avo"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""446"",
    ""smallest_denomination"": 10
  },
  ""mro"": {
    ""priority"": 100,
    ""iso_code"": ""MRO"",
    ""name"": ""Mauritanian Ouguiya"",
    ""symbol"": ""UM"",
    ""alternate_symbols"": [],
    ""subunit"": ""Khoums"",
    ""subunit_to_unit"": 5,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""478"",
    ""smallest_denomination"": 1
  },
  ""mur"": {
    ""priority"": 100,
    ""iso_code"": ""MUR"",
    ""name"": ""Mauritian Rupee"",
    ""symbol"": ""₨"",
    ""alternate_symbols"": [],
    ""subunit"": ""Cent"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""&#x20A8;"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""480"",
    ""smallest_denomination"": 100
  },
  ""mvr"": {
    ""priority"": 100,
    ""iso_code"": ""MVR"",
    ""name"": ""Maldivian Rufiyaa"",
    ""symbol"": ""MVR"",
    ""alternate_symbols"": [""MRF"", ""Rf"", ""/-"", ""ރ""],
    ""subunit"": ""Laari"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""462"",
    ""smallest_denomination"": 1
  },
  ""mwk"": {
    ""priority"": 100,
    ""iso_code"": ""MWK"",
    ""name"": ""Malawian Kwacha"",
    ""symbol"": ""MK"",
    ""alternate_symbols"": [],
    ""subunit"": ""Tambala"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""454"",
    ""smallest_denomination"": 1
  },
  ""mxn"": {
    ""priority"": 100,
    ""iso_code"": ""MXN"",
    ""name"": ""Mexican Peso"",
    ""symbol"": ""$"",
    ""disambiguate_symbol"": ""MEX$"",
    ""alternate_symbols"": [""MEX$""],
    ""subunit"": ""Centavo"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""$"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""484"",
    ""smallest_denomination"": 5
  },
  ""myr"": {
    ""priority"": 100,
    ""iso_code"": ""MYR"",
    ""name"": ""Malaysian Ringgit"",
    ""symbol"": ""RM"",
    ""alternate_symbols"": [],
    ""subunit"": ""Sen"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""458"",
    ""smallest_denomination"": 5
  },
  ""mzn"": {
    ""priority"": 100,
    ""iso_code"": ""MZN"",
    ""name"": ""Mozambican Metical"",
    ""symbol"": ""MTn"",
    ""alternate_symbols"": [""MZN""],
    ""subunit"": ""Centavo"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": """",
    ""decimal_mark"": "","",
    ""thousands_separator"": ""."",
    ""iso_numeric"": ""943"",
    ""smallest_denomination"": 1
  },
  ""nad"": {
    ""priority"": 100,
    ""iso_code"": ""NAD"",
    ""name"": ""Namibian Dollar"",
    ""symbol"": ""$"",
    ""disambiguate_symbol"": ""N$"",
    ""alternate_symbols"": [""N$""],
    ""subunit"": ""Cent"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": ""$"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""516"",
    ""smallest_denomination"": 5
  },
  ""ngn"": {
    ""priority"": 100,
    ""iso_code"": ""NGN"",
    ""name"": ""Nigerian Naira"",
    ""symbol"": ""₦"",
    ""alternate_symbols"": [],
    ""subunit"": ""Kobo"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""&#x20A6;"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""566"",
    ""smallest_denomination"": 50
  },
  ""nio"": {
    ""priority"": 100,
    ""iso_code"": ""NIO"",
    ""name"": ""Nicaraguan Córdoba"",
    ""symbol"": ""C$"",
    ""alternate_symbols"": [],
    ""subunit"": ""Centavo"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""558"",
    ""smallest_denomination"": 5
  },
  ""nok"": {
    ""priority"": 100,
    ""iso_code"": ""NOK"",
    ""name"": ""Norwegian Krone"",
    ""symbol"": ""kr"",
    ""disambiguate_symbol"": ""NOK"",
    ""alternate_symbols"": ["",-""],
    ""subunit"": ""Øre"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": ""kr"",
    ""decimal_mark"": "","",
    ""thousands_separator"": ""."",
    ""iso_numeric"": ""578"",
    ""smallest_denomination"": 100
  },
  ""npr"": {
    ""priority"": 100,
    ""iso_code"": ""NPR"",
    ""name"": ""Nepalese Rupee"",
    ""symbol"": ""₨"",
    ""disambiguate_symbol"": ""NPR"",
    ""alternate_symbols"": [""Rs"", ""रू""],
    ""subunit"": ""Paisa"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""&#x20A8;"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""524"",
    ""smallest_denomination"": 1
  },
  ""nzd"": {
    ""priority"": 100,
    ""iso_code"": ""NZD"",
    ""name"": ""New Zealand Dollar"",
    ""symbol"": ""$"",
    ""disambiguate_symbol"": ""NZ$"",
    ""alternate_symbols"": [""NZ$""],
    ""subunit"": ""Cent"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""$"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""554"",
    ""smallest_denomination"": 10
  },
  ""omr"": {
    ""priority"": 100,
    ""iso_code"": ""OMR"",
    ""name"": ""Omani Rial"",
    ""symbol"": ""ر.ع."",
    ""alternate_symbols"": [],
    ""subunit"": ""Baisa"",
    ""subunit_to_unit"": 1000,
    ""symbol_first"": true,
    ""html_entity"": ""&#xFDFC;"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""512"",
    ""smallest_denomination"": 5
  },
  ""pab"": {
    ""priority"": 100,
    ""iso_code"": ""PAB"",
    ""name"": ""Panamanian Balboa"",
    ""symbol"": ""B/."",
    ""alternate_symbols"": [],
    ""subunit"": ""Centésimo"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""590"",
    ""smallest_denomination"": 1
  },
  ""pen"": {
    ""priority"": 100,
    ""iso_code"": ""PEN"",
    ""name"": ""Peruvian Nuevo Sol"",
    ""symbol"": ""S/."",
    ""alternate_symbols"": [],
    ""subunit"": ""Céntimo"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""S/."",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""604"",
    ""smallest_denomination"": 1
  },
  ""pgk"": {
    ""priority"": 100,
    ""iso_code"": ""PGK"",
    ""name"": ""Papua New Guinean Kina"",
    ""symbol"": ""K"",
    ""disambiguate_symbol"": ""PGK"",
    ""alternate_symbols"": [],
    ""subunit"": ""Toea"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""598"",
    ""smallest_denomination"": 5
  },
  ""php"": {
    ""priority"": 100,
    ""iso_code"": ""PHP"",
    ""name"": ""Philippine Peso"",
    ""symbol"": ""₱"",
    ""alternate_symbols"": [""PHP"", ""PhP"", ""P""],
    ""subunit"": ""Centavo"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""&#x20B1;"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""608"",
    ""smallest_denomination"": 1
  },
  ""pkr"": {
    ""priority"": 100,
    ""iso_code"": ""PKR"",
    ""name"": ""Pakistani Rupee"",
    ""symbol"": ""₨"",
    ""disambiguate_symbol"": ""PKR"",
    ""alternate_symbols"": [""Rs""],
    ""subunit"": ""Paisa"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""&#x20A8;"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""586"",
    ""smallest_denomination"": 100
  },
  ""pln"": {
    ""priority"": 100,
    ""iso_code"": ""PLN"",
    ""name"": ""Polish Złoty"",
    ""symbol"": ""zł"",
    ""alternate_symbols"": [],
    ""subunit"": ""Grosz"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": ""z&#322;"",
    ""decimal_mark"": "","",
    ""thousands_separator"": "" "",
    ""iso_numeric"": ""985"",
    ""smallest_denomination"": 1
  },
  ""pyg"": {
    ""priority"": 100,
    ""iso_code"": ""PYG"",
    ""name"": ""Paraguayan Guaraní"",
    ""symbol"": ""₲"",
    ""alternate_symbols"": [],
    ""subunit"": ""Céntimo"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""&#x20B2;"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""600"",
    ""smallest_denomination"": 5000
  },
  ""qar"": {
    ""priority"": 100,
    ""iso_code"": ""QAR"",
    ""name"": ""Qatari Riyal"",
    ""symbol"": ""ر.ق"",
    ""alternate_symbols"": [""QR""],
    ""subunit"": ""Dirham"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": ""&#xFDFC;"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""634"",
    ""smallest_denomination"": 1
  },
  ""ron"": {
    ""priority"": 100,
    ""iso_code"": ""RON"",
    ""name"": ""Romanian Leu"",
    ""symbol"": ""Lei"",
    ""alternate_symbols"": [],
    ""subunit"": ""Bani"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": """",
    ""decimal_mark"": "","",
    ""thousands_separator"": ""."",
    ""iso_numeric"": ""946"",
    ""smallest_denomination"": 1
  },
  ""rsd"": {
    ""priority"": 100,
    ""iso_code"": ""RSD"",
    ""name"": ""Serbian Dinar"",
    ""symbol"": ""РСД"",
    ""alternate_symbols"": [""RSD"", ""din"", ""дин""],
    ""subunit"": ""Para"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""941"",
    ""smallest_denomination"": 100
  },
  ""rub"": {
    ""priority"": 100,
    ""iso_code"": ""RUB"",
    ""name"": ""Russian Ruble"",
    ""symbol"": ""₽"",
    ""alternate_symbols"": [""руб."", ""р.""],
    ""subunit"": ""Kopeck"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": ""&#x20BD;"",
    ""decimal_mark"": "","",
    ""thousands_separator"": ""."",
    ""iso_numeric"": ""643"",
    ""smallest_denomination"": 1
  },
  ""rwf"": {
    ""priority"": 100,
    ""iso_code"": ""RWF"",
    ""name"": ""Rwandan Franc"",
    ""symbol"": ""FRw"",
    ""alternate_symbols"": [""RF"", ""R₣""],
    ""subunit"": ""Centime"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""646"",
    ""smallest_denomination"": 100
  },
  ""sar"": {
    ""priority"": 100,
    ""iso_code"": ""SAR"",
    ""name"": ""Saudi Riyal"",
    ""symbol"": ""ر.س"",
    ""alternate_symbols"": [""SR"", ""﷼""],
    ""subunit"": ""Hallallah"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""&#xFDFC;"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""682"",
    ""smallest_denomination"": 5
  },
  ""sbd"": {
    ""priority"": 100,
    ""iso_code"": ""SBD"",
    ""name"": ""Solomon Islands Dollar"",
    ""symbol"": ""$"",
    ""disambiguate_symbol"": ""SI$"",
    ""alternate_symbols"": [""SI$""],
    ""subunit"": ""Cent"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": ""$"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""090"",
    ""smallest_denomination"": 10
  },
  ""scr"": {
    ""priority"": 100,
    ""iso_code"": ""SCR"",
    ""name"": ""Seychellois Rupee"",
    ""symbol"": ""₨"",
    ""disambiguate_symbol"": ""SRe"",
    ""alternate_symbols"": [""SRe"", ""SR""],
    ""subunit"": ""Cent"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": ""&#x20A8;"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""690"",
    ""smallest_denomination"": 1
  },
  ""sdg"": {
    ""priority"": 100,
    ""iso_code"": ""SDG"",
    ""name"": ""Sudanese Pound"",
    ""symbol"": ""£"",
    ""disambiguate_symbol"": ""SDG"",
    ""alternate_symbols"": [],
    ""subunit"": ""Piastre"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""938"",
    ""smallest_denomination"": 1
  },
  ""sek"": {
    ""priority"": 100,
    ""iso_code"": ""SEK"",
    ""name"": ""Swedish Krona"",
    ""symbol"": ""kr"",
    ""disambiguate_symbol"": ""SEK"",
    ""alternate_symbols"": ["":-""],
    ""subunit"": ""Öre"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": "","",
    ""thousands_separator"": "" "",
    ""iso_numeric"": ""752"",
    ""smallest_denomination"": 100
  },
  ""sgd"": {
    ""priority"": 100,
    ""iso_code"": ""SGD"",
    ""name"": ""Singapore Dollar"",
    ""symbol"": ""$"",
    ""disambiguate_symbol"": ""S$"",
    ""alternate_symbols"": [""S$""],
    ""subunit"": ""Cent"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""$"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""702"",
    ""smallest_denomination"": 1
  },
  ""shp"": {
    ""priority"": 100,
    ""iso_code"": ""SHP"",
    ""name"": ""Saint Helenian Pound"",
    ""symbol"": ""£"",
    ""disambiguate_symbol"": ""SHP"",
    ""alternate_symbols"": [],
    ""subunit"": ""Penny"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": ""&#x00A3;"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""654"",
    ""smallest_denomination"": 1
  },
  ""skk"": {
    ""priority"": 100,
    ""iso_code"": ""SKK"",
    ""name"": ""Slovak Koruna"",
    ""symbol"": ""Sk"",
    ""alternate_symbols"": [],
    ""subunit"": ""Halier"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""703"",
    ""smallest_denomination"": 50
  },
  ""sll"": {
    ""priority"": 100,
    ""iso_code"": ""SLL"",
    ""name"": ""Sierra Leonean Leone"",
    ""symbol"": ""Le"",
    ""alternate_symbols"": [],
    ""subunit"": ""Cent"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""694"",
    ""smallest_denomination"": 1000
  },
  ""sos"": {
    ""priority"": 100,
    ""iso_code"": ""SOS"",
    ""name"": ""Somali Shilling"",
    ""symbol"": ""Sh"",
    ""alternate_symbols"": [""Sh.So""],
    ""subunit"": ""Cent"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""706"",
    ""smallest_denomination"": 1
  },
  ""srd"": {
    ""priority"": 100,
    ""iso_code"": ""SRD"",
    ""name"": ""Surinamese Dollar"",
    ""symbol"": ""$"",
    ""disambiguate_symbol"": ""SRD"",
    ""alternate_symbols"": [],
    ""subunit"": ""Cent"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""968"",
    ""smallest_denomination"": 1
  },
  ""ssp"": {
    ""priority"": 100,
    ""iso_code"": ""SSP"",
    ""name"": ""South Sudanese Pound"",
    ""symbol"": ""£"",
    ""disambiguate_symbol"": ""SSP"",
    ""alternate_symbols"": [],
    ""subunit"": ""piaster"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": ""&#x00A3;"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""728"",
    ""smallest_denomination"": 5
  },
  ""std"": {
    ""priority"": 100,
    ""iso_code"": ""STD"",
    ""name"": ""São Tomé and Príncipe Dobra"",
    ""symbol"": ""Db"",
    ""alternate_symbols"": [],
    ""subunit"": ""Cêntimo"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""678"",
    ""smallest_denomination"": 10000
  },
  ""svc"": {
    ""priority"": 100,
    ""iso_code"": ""SVC"",
    ""name"": ""Salvadoran Colón"",
    ""symbol"": ""₡"",
    ""alternate_symbols"": [""¢""],
    ""subunit"": ""Centavo"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""&#x20A1;"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""222"",
    ""smallest_denomination"": 1
  },
  ""syp"": {
    ""priority"": 100,
    ""iso_code"": ""SYP"",
    ""name"": ""Syrian Pound"",
    ""symbol"": ""£S"",
    ""alternate_symbols"": [""£"", ""ل.س"", ""LS"", ""الليرة السورية""],
    ""subunit"": ""Piastre"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": ""&#x00A3;"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""760"",
    ""smallest_denomination"": 100
  },
  ""szl"": {
    ""priority"": 100,
    ""iso_code"": ""SZL"",
    ""name"": ""Swazi Lilangeni"",
    ""symbol"": ""E"",
    ""disambiguate_symbol"": ""SZL"",
    ""subunit"": ""Cent"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""748"",
    ""smallest_denomination"": 1
  },
  ""thb"": {
    ""priority"": 100,
    ""iso_code"": ""THB"",
    ""name"": ""Thai Baht"",
    ""symbol"": ""฿"",
    ""alternate_symbols"": [],
    ""subunit"": ""Satang"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""&#x0E3F;"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""764"",
    ""smallest_denomination"": 1
  },
  ""tjs"": {
    ""priority"": 100,
    ""iso_code"": ""TJS"",
    ""name"": ""Tajikistani Somoni"",
    ""symbol"": ""ЅМ"",
    ""alternate_symbols"": [],
    ""subunit"": ""Diram"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""972"",
    ""smallest_denomination"": 1
  },
  ""tmt"": {
    ""priority"": 100,
    ""iso_code"": ""TMT"",
    ""name"": ""Turkmenistani Manat"",
    ""symbol"": ""T"",
    ""alternate_symbols"": [],
    ""subunit"": ""Tenge"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""934"",
    ""smallest_denomination"": 1
  },
  ""tnd"": {
    ""priority"": 100,
    ""iso_code"": ""TND"",
    ""name"": ""Tunisian Dinar"",
    ""symbol"": ""د.ت"",
    ""alternate_symbols"": [""TD"", ""DT""],
    ""subunit"": ""Millime"",
    ""subunit_to_unit"": 1000,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""788"",
    ""smallest_denomination"": 10
  },
  ""top"": {
    ""priority"": 100,
    ""iso_code"": ""TOP"",
    ""name"": ""Tongan Paʻanga"",
    ""symbol"": ""T$"",
    ""alternate_symbols"": [""PT""],
    ""subunit"": ""Seniti"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""776"",
    ""smallest_denomination"": 1
  },
  ""try"": {
    ""priority"": 100,
    ""iso_code"": ""TRY"",
    ""name"": ""Turkish Lira"",
    ""symbol"": ""₺"",
    ""alternate_symbols"": [""TL""],
    ""subunit"": ""kuruş"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""&#8378;"",
    ""decimal_mark"": "","",
    ""thousands_separator"": ""."",
    ""iso_numeric"": ""949"",
    ""smallest_denomination"": 1
  },
  ""ttd"": {
    ""priority"": 100,
    ""iso_code"": ""TTD"",
    ""name"": ""Trinidad and Tobago Dollar"",
    ""symbol"": ""$"",
    ""disambiguate_symbol"": ""TT$"",
    ""alternate_symbols"": [""TT$""],
    ""subunit"": ""Cent"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": ""$"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""780"",
    ""smallest_denomination"": 1
  },
  ""twd"": {
    ""priority"": 100,
    ""iso_code"": ""TWD"",
    ""name"": ""New Taiwan Dollar"",
    ""symbol"": ""$"",
    ""disambiguate_symbol"": ""NT$"",
    ""alternate_symbols"": [""NT$""],
    ""subunit"": ""Cent"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""$"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""901"",
    ""smallest_denomination"": 50
  },
  ""tzs"": {
    ""priority"": 100,
    ""iso_code"": ""TZS"",
    ""name"": ""Tanzanian Shilling"",
    ""symbol"": ""Sh"",
    ""alternate_symbols"": [],
    ""subunit"": ""Cent"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""834"",
    ""smallest_denomination"": 5000
  },
  ""uah"": {
    ""priority"": 100,
    ""iso_code"": ""UAH"",
    ""name"": ""Ukrainian Hryvnia"",
    ""symbol"": ""₴"",
    ""alternate_symbols"": [],
    ""subunit"": ""Kopiyka"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": ""&#x20B4;"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""980"",
    ""smallest_denomination"": 1
  },
  ""ugx"": {
    ""priority"": 100,
    ""iso_code"": ""UGX"",
    ""name"": ""Ugandan Shilling"",
    ""symbol"": ""USh"",
    ""alternate_symbols"": [],
    ""subunit"": ""Cent"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""800"",
    ""smallest_denomination"": 1000
  },
  ""usd"": {
    ""priority"": 1,
    ""iso_code"": ""USD"",
    ""name"": ""United States Dollar"",
    ""symbol"": ""$"",
    ""alternate_symbols"": [""US$""],
    ""subunit"": ""Cent"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""$"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""840"",
    ""smallest_denomination"": 1
  },
  ""uyu"": {
    ""priority"": 100,
    ""iso_code"": ""UYU"",
    ""name"": ""Uruguayan Peso"",
    ""symbol"": ""$"",
    ""alternate_symbols"": [""$U""],
    ""subunit"": ""Centésimo"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""&#x20B1;"",
    ""decimal_mark"": "","",
    ""thousands_separator"": ""."",
    ""iso_numeric"": ""858"",
    ""smallest_denomination"": 100
  },
  ""uzs"": {
    ""priority"": 100,
    ""iso_code"": ""UZS"",
    ""name"": ""Uzbekistani Som"",
    ""symbol"": null,
    ""alternate_symbols"": [],
    ""subunit"": ""Tiyin"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""860"",
    ""smallest_denomination"": 100
  },
  ""vef"": {
    ""priority"": 100,
    ""iso_code"": ""VEF"",
    ""name"": ""Venezuelan Bolívar"",
    ""symbol"": ""Bs"",
    ""alternate_symbols"": [""Bs.F""],
    ""subunit"": ""Céntimo"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": """",
    ""decimal_mark"": "","",
    ""thousands_separator"": ""."",
    ""iso_numeric"": ""937"",
    ""smallest_denomination"": 1
  },
  ""vnd"": {
    ""priority"": 100,
    ""iso_code"": ""VND"",
    ""name"": ""Vietnamese Đồng"",
    ""symbol"": ""₫"",
    ""alternate_symbols"": [],
    ""subunit"": ""Hào"",
    ""subunit_to_unit"": 1,
    ""symbol_first"": true,
    ""html_entity"": ""&#x20AB;"",
    ""decimal_mark"": "","",
    ""thousands_separator"": ""."",
    ""iso_numeric"": ""704"",
    ""smallest_denomination"": 100
  },
  ""vuv"": {
    ""priority"": 100,
    ""iso_code"": ""VUV"",
    ""name"": ""Vanuatu Vatu"",
    ""symbol"": ""Vt"",
    ""alternate_symbols"": [],
    ""subunit"": null,
    ""subunit_to_unit"": 1,
    ""symbol_first"": true,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""548"",
    ""smallest_denomination"": 1
  },
  ""wst"": {
    ""priority"": 100,
    ""iso_code"": ""WST"",
    ""name"": ""Samoan Tala"",
    ""symbol"": ""T"",
    ""disambiguate_symbol"": ""WS$"",
    ""alternate_symbols"": [""WS$"", ""SAT"", ""ST""],
    ""subunit"": ""Sene"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""882"",
    ""smallest_denomination"": 10
  },
  ""xaf"": {
    ""priority"": 100,
    ""iso_code"": ""XAF"",
    ""name"": ""Central African Cfa Franc"",
    ""symbol"": ""Fr"",
    ""disambiguate_symbol"": ""FCFA"",
    ""alternate_symbols"": [""FCFA""],
    ""subunit"": ""Centime"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""950"",
    ""smallest_denomination"": 100
  },
  ""xag"": {
    ""priority"": 100,
    ""iso_code"": ""XAG"",
    ""name"": ""Silver (Troy Ounce)"",
    ""symbol"": ""oz t"",
    ""disambiguate_symbol"": ""XAG"",
    ""alternate_symbols"": [],
    ""subunit"": ""oz"",
    ""subunit_to_unit"": 1,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""961""
  },
  ""xau"": {
    ""priority"": 100,
    ""iso_code"": ""XAU"",
    ""name"": ""Gold (Troy Ounce)"",
    ""symbol"": ""oz t"",
    ""disambiguate_symbol"": ""XAU"",
    ""alternate_symbols"": [],
    ""subunit"": ""oz"",
    ""subunit_to_unit"": 1,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""959""
  },
  ""xcd"": {
    ""priority"": 100,
    ""iso_code"": ""XCD"",
    ""name"": ""East Caribbean Dollar"",
    ""symbol"": ""$"",
    ""disambiguate_symbol"": ""EX$"",
    ""alternate_symbols"": [""EC$""],
    ""subunit"": ""Cent"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""$"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""951"",
    ""smallest_denomination"": 1
  },
  ""xdr"": {
    ""priority"": 100,
    ""iso_code"": ""XDR"",
    ""name"": ""Special Drawing Rights"",
    ""symbol"": ""SDR"",
    ""alternate_symbols"": [""XDR""],
    ""subunit"": """",
    ""subunit_to_unit"": 1,
    ""symbol_first"": false,
    ""html_entity"": ""$"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""960""
  },
  ""xof"": {
    ""priority"": 100,
    ""iso_code"": ""XOF"",
    ""name"": ""West African Cfa Franc"",
    ""symbol"": ""Fr"",
    ""disambiguate_symbol"": ""CFA"",
    ""alternate_symbols"": [""CFA""],
    ""subunit"": ""Centime"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""952"",
    ""smallest_denomination"": 100
  },
  ""xpf"": {
    ""priority"": 100,
    ""iso_code"": ""XPF"",
    ""name"": ""Cfp Franc"",
    ""symbol"": ""Fr"",
    ""alternate_symbols"": [""F""],
    ""subunit"": ""Centime"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""953"",
    ""smallest_denomination"": 100
  },
  ""yer"": {
    ""priority"": 100,
    ""iso_code"": ""YER"",
    ""name"": ""Yemeni Rial"",
    ""symbol"": ""﷼"",
    ""alternate_symbols"": [],
    ""subunit"": ""Fils"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": ""&#xFDFC;"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""886"",
    ""smallest_denomination"": 100
  },
  ""zar"": {
    ""priority"": 100,
    ""iso_code"": ""ZAR"",
    ""name"": ""South African Rand"",
    ""symbol"": ""R"",
    ""alternate_symbols"": [],
    ""subunit"": ""Cent"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": true,
    ""html_entity"": ""&#x0052;"",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""710"",
    ""smallest_denomination"": 10
  },
  ""zmk"": {
    ""priority"": 100,
    ""iso_code"": ""ZMK"",
    ""name"": ""Zambian Kwacha"",
    ""symbol"": ""ZK"",
    ""disambiguate_symbol"": ""ZMK"",
    ""alternate_symbols"": [],
    ""subunit"": ""Ngwee"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""894"",
    ""smallest_denomination"": 5
  },
  ""zmw"": {
    ""priority"": 100,
    ""iso_code"": ""ZMW"",
    ""name"": ""Zambian Kwacha"",
    ""symbol"": ""ZK"",
    ""disambiguate_symbol"": ""ZMW"",
    ""alternate_symbols"": [],
    ""subunit"": ""Ngwee"",
    ""subunit_to_unit"": 100,
    ""symbol_first"": false,
    ""html_entity"": """",
    ""decimal_mark"": ""."",
    ""thousands_separator"": "","",
    ""iso_numeric"": ""967"",
    ""smallest_denomination"": 5
  }
}";
			#endregion
			var currencyObj = (JObject)JsonConvert.DeserializeObject(currencyJson);

			foreach (var property in currencyObj)
			{
				var objectJson = JsonConvert.SerializeObject(property.Value);
				var currency = JsonConvert.DeserializeObject<Currency>(objectJson);
				result.Add(currency);
			}
			result = result.OrderBy(x => x.Priority).ToList();

			return result;
		}

		public static Currency GetCurrency(string currencyCode)
		{
			return GetAllCurrency().FirstOrDefault(x => x.IsoCode.ToLowerInvariant() == currencyCode.ToLowerInvariant());
		}

		public static List<CurrencyType> GetAllCurrencyType()
		{
			return GetAllCurrency().MapTo<CurrencyType>();
		}

		public static CurrencyType GetCurrencyType(string currencyCode)
		{
			CurrencyType result = null;
			var currency = GetCurrency(currencyCode);

			if (currency != null)
			{
				result = currency.MapTo<CurrencyType>();
			}
			return result;
		}

		//public static T DeepClone<T>(T obj)
		//{
		//	using (var ms = new MemoryStream())
		//	{
		//		var formatter = new BinaryFormatter();
		//		formatter.Serialize(ms, obj);
		//		ms.Position = 0;

		//		return (T)formatter.Deserialize(ms);
		//	}
		//}

		public static EntityRecord FixDoubleDollarSignProblem(EntityRecord record)
		{
			var keysForRemoval = new List<string>();
			var recordKeyList = new List<string>();

			foreach (var property in record.Properties)
			{
				recordKeyList.Add(property.Key);
			}

			//in angular properties starting with $$ are not posted by the $http service, 
			foreach (var key in recordKeyList)
			{
				if (key.StartsWith("_$"))
				{
					var newKey = "$$" + key.Remove(0, 2);
					record[newKey] = record[key];
					keysForRemoval.Add(key);
				}
			}

			foreach (var key in keysForRemoval)
			{
				record.Properties.Remove(key);
			}
			return record;
		}

		// THREAT ADDRESSED - review finding M-08 (CWE-400 uncontrolled resource consumption, and CWE-1188
		// platform-specific behaviour relied upon on a platform that does not provide it), OWASP A04
		// Insecure Design. Two defects sat in one four-line method, and the CA1416 suppression that used to
		// bracket it was what kept both of them invisible.
		//
		// (1) NOT AVAILABLE ON THE DEPLOYMENT PLATFORM. System.Drawing.Image.FromStream is a Windows-only
		// GDI+ facade. On .NET 10 running on Linux it does not degrade - it throws
		// TypeInitializationException from Windows.Win32.PInvokeGdiPlus, measured directly on this
		// platform. Every caller reaches this method from inside an "if the MIME type starts with image"
		// branch of an upload path, and none of them catches it locally, so on Linux EVERY image upload
		// failed: the platform's own accept-image policy admitted the file and then the persistence step
		// threw. The CA1416 suppression asserted the opposite of the truth - it declared the platform
		// question reviewed and settled - which is precisely why this was never surfaced by the analyzer
		// gate. The suppression is removed rather than moved.
		//
		// (2) UNBOUNDED DECODE. FromStream DECODES the image to construct the object, so the work and the
		// memory it consumed were a function of the declared pixel dimensions rather than of the byte
		// length that the upload size cap actually bounds. A few kilobytes of highly compressed pixel data
		// can declare hundreds of megapixels - the "decompression bomb" shape - so an authenticated caller
		// could exhaust the process from well inside the size limit.
		//
		// THE FIX IS TO STOP DECODING. Every format this platform admits on upload carries its pixel
		// dimensions in a fixed-offset header, so the dimensions are READ rather than derived: constant
		// work, a bounded number of leading bytes examined, no pixel buffer allocated, and no platform
		// dependency. That is also the least invasive control available - it needs no package (OWASP
		// Dependency Updates / AAP "no new package dependency"), and it keeps the returned
		// EntityRecord contract identical for every file that previously succeeded.
		//
		// The dimension BOUND that closes the resource-consumption half is enforced by the caller, at the
		// single upload choke point every upload action already passes through
		// (WebApiController.GetUploadContentRejectionReason), because a refusal there returns the
		// endpoint's own standard error envelope. This method's own contract is only to report or to
		// decline to report; see the remarks below.

		// Upper bound on the number of leading bytes any of the readers below will examine. TIFF is the
		// only format whose dimension tags are not at a fixed small offset - they sit behind an image file
		// directory whose position the header declares - so the probe window has to be wide enough to
		// reach a normal directory while still being a hard, constant bound rather than "as far as it
		// takes". 64 KiB reaches the directory of every TIFF a browser or camera produces; a file that
		// hides its directory beyond that simply reports no dimensions rather than being chased.
		private const int MAX_IMAGE_HEADER_PROBE_BYTES = 64 * 1024;

		/// <summary>
		/// Reads the pixel dimensions of an image from its header, without decoding it.
		/// </summary>
		/// <remarks>
		/// Review finding M-08. Returns an <see cref="EntityRecord"/> carrying decimal "width" and
		/// "height" when the dimensions can be read, and <c>null</c> when they cannot.
		/// <para>
		/// RETURNING NULL RATHER THAN THROWING IS PART OF THE CONTRACT. This method sits on upload paths
		/// whose type policy is enforced by an extension allow-list and a leading-signature check, not by
		/// this method, so a file that is admitted but whose header this reader does not recognise must
		/// not become a failed upload - and a malformed or truncated header must never become an
		/// unhandled fault on a request path, which would hand an authenticated caller a denial-of-service
		/// primitive. Callers therefore treat a null result as "dimensions unknown" and persist the record
		/// without the width and height fields, exactly as they already do for a non-image file.
		/// </para>
		/// <para>
		/// Formats covered are those the upload allow-list admits: PNG, JPEG, GIF, BMP, WEBP, ICO and
		/// TIFF. SVG is deliberately absent because it is deliberately absent from the upload allow-list:
		/// it is an XML document that can carry script, and it has no pixel dimensions to read.
		/// </para>
		/// </remarks>
		public static EntityRecord GetImageDimension(byte[] imageContent)
		{
			var dimensions = ReadImageDimensions(imageContent);
			if (dimensions == null)
			{
				return null;
			}

			var response = new EntityRecord();
			response["width"] = (decimal)dimensions.Value.Width;
			response["height"] = (decimal)dimensions.Value.Height;
			return response;
		}

		/// <summary>
		/// Reads the pixel dimensions of an image from its header, or returns null when they cannot be
		/// determined. Never throws for malformed, truncated or unrecognised content.
		/// </summary>
		/// <remarks>
		/// Review finding M-08. Separated from <see cref="GetImageDimension"/> so a caller that needs to
		/// BOUND the dimensions before persisting anything - the upload rejection check - can read them
		/// without allocating a record, and so the two callers cannot drift apart on what "unknown" means.
		/// </remarks>
		public static (int Width, int Height)? ReadImageDimensions(byte[] imageContent)
		{
			if (imageContent == null || imageContent.Length < 8)
			{
				return null;
			}

			try
			{
				//PNG - the IHDR chunk is specified to be the first chunk, so width and height sit at fixed
				//offsets 16 and 20, big-endian.
				if (StartsWith(imageContent, PngSignature))
				{
					if (imageContent.Length < 24)
					{
						return null;
					}

					return Bound(ReadInt32BigEndian(imageContent, 16), ReadInt32BigEndian(imageContent, 20));
				}

				//GIF - the logical screen descriptor follows the six-byte version signature, little-endian.
				if (StartsWith(imageContent, Gif87aSignature) || StartsWith(imageContent, Gif89aSignature))
				{
					if (imageContent.Length < 10)
					{
						return null;
					}

					return Bound(ReadUInt16LittleEndian(imageContent, 6), ReadUInt16LittleEndian(imageContent, 8));
				}

				//BMP - the DIB header follows the 14-byte file header. Its own size field distinguishes the
				//12-byte BITMAPCOREHEADER, whose dimensions are 16-bit, from every later header, whose
				//dimensions are signed 32-bit. Height is negative for a top-down bitmap, so it is taken as
				//an absolute value.
				if (StartsWith(imageContent, BmpSignature))
				{
					if (imageContent.Length < 26)
					{
						return null;
					}

					var dibHeaderSize = ReadInt32LittleEndian(imageContent, 14);
					if (dibHeaderSize == 12)
					{
						return Bound(ReadUInt16LittleEndian(imageContent, 18), ReadUInt16LittleEndian(imageContent, 20));
					}

					var bmpWidth = ReadInt32LittleEndian(imageContent, 18);
					var bmpHeight = ReadInt32LittleEndian(imageContent, 22);
					return Bound(Math.Abs((long)bmpWidth), Math.Abs((long)bmpHeight));
				}

				//WEBP - a RIFF container whose fourth chunk word is "WEBP". Three codec chunks exist and
				//each carries its dimensions differently, which is why the extension's leading-signature
				//check cannot reach them and this reader has to.
				if (StartsWith(imageContent, RiffSignature) && HasAsciiTag(imageContent, 8, "WEBP"))
				{
					return ReadWebpDimensions(imageContent);
				}

				//ICO - an icon directory rather than a single image.
				if (StartsWith(imageContent, IcoSignature))
				{
					return ReadIcoDimensions(imageContent);
				}

				//TIFF - little- and big-endian variants. The dimensions live in tags 0x0100 and 0x0101 of
				//the first image file directory, whose offset the header declares.
				if (StartsWith(imageContent, TiffLittleEndianSignature))
				{
					return ReadTiffDimensions(imageContent, false);
				}

				if (StartsWith(imageContent, TiffBigEndianSignature))
				{
					return ReadTiffDimensions(imageContent, true);
				}

				//JPEG - a marker stream, so the frame header has to be walked to rather than indexed.
				if (StartsWith(imageContent, JpegSignature))
				{
					return ReadJpegDimensions(imageContent);
				}
			}
			catch (Exception)
			{
				//M-08: unreachable by construction - every read below is index-guarded - but retained as
				//the outer guarantee behind the documented contract, because this method is called on
				//attacker-supplied bytes and "returns null" must hold for every input without exception.
				return null;
			}

			return null;
		}

		private static readonly byte[] PngSignature = { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
		private static readonly byte[] Gif87aSignature = { 0x47, 0x49, 0x46, 0x38, 0x37, 0x61 };
		private static readonly byte[] Gif89aSignature = { 0x47, 0x49, 0x46, 0x38, 0x39, 0x61 };
		private static readonly byte[] BmpSignature = { 0x42, 0x4D };
		private static readonly byte[] RiffSignature = { 0x52, 0x49, 0x46, 0x46 };
		private static readonly byte[] IcoSignature = { 0x00, 0x00, 0x01, 0x00 };
		private static readonly byte[] TiffLittleEndianSignature = { 0x49, 0x49, 0x2A, 0x00 };
		private static readonly byte[] TiffBigEndianSignature = { 0x4D, 0x4D, 0x00, 0x2A };
		private static readonly byte[] JpegSignature = { 0xFF, 0xD8, 0xFF };

		private static bool StartsWith(byte[] content, byte[] signature)
		{
			if (content.Length < signature.Length)
			{
				return false;
			}

			for (var index = 0; index < signature.Length; index++)
			{
				if (content[index] != signature[index])
				{
					return false;
				}
			}

			return true;
		}

		private static bool HasAsciiTag(byte[] content, int offset, string tag)
		{
			if (offset < 0 || content.Length < offset + tag.Length)
			{
				return false;
			}

			for (var index = 0; index < tag.Length; index++)
			{
				if (content[offset + index] != (byte)tag[index])
				{
					return false;
				}
			}

			return true;
		}

		private static long ReadInt32BigEndian(byte[] content, int offset)
		{
			return ((long)content[offset] << 24) | ((long)content[offset + 1] << 16) | ((long)content[offset + 2] << 8) | content[offset + 3];
		}

		private static int ReadInt32LittleEndian(byte[] content, int offset)
		{
			return content[offset] | (content[offset + 1] << 8) | (content[offset + 2] << 16) | (content[offset + 3] << 24);
		}

		private static long ReadUInt16LittleEndian(byte[] content, int offset)
		{
			return content[offset] | ((long)content[offset + 1] << 8);
		}

		private static long ReadUInt16BigEndian(byte[] content, int offset)
		{
			return ((long)content[offset] << 8) | content[offset + 1];
		}

		/// <summary>
		/// Rejects a non-positive or implausible dimension pair rather than reporting it.
		/// </summary>
		/// <remarks>
		/// Review finding M-08. A header is caller-supplied data, so a value read from one is a claim and
		/// not a fact. Anything outside a sane range is reported as unknown, which keeps a crafted header
		/// from reaching the record fields or the caller's bound arithmetic. The ceiling is deliberately
		/// far above any real photograph so no legitimate image is refused by it; the ACTUAL pixel policy
		/// is the caller's, at the upload choke point.
		/// </remarks>
		private static (int Width, int Height)? Bound(long width, long height)
		{
			const long absoluteMaximumEdge = 1000000;
			if (width <= 0 || height <= 0 || width > absoluteMaximumEdge || height > absoluteMaximumEdge)
			{
				return null;
			}

			return ((int)width, (int)height);
		}

		private static (int Width, int Height)? ReadWebpDimensions(byte[] content)
		{
			//The codec chunk follows the twelve-byte RIFF/WEBP preamble.
			if (content.Length < 30)
			{
				return null;
			}

			//Lossy: a VP8 bitstream whose 14-byte frame header ends with two 14-bit dimensions.
			if (HasAsciiTag(content, 12, "VP8 "))
			{
				return Bound(ReadUInt16LittleEndian(content, 26) & 0x3FFF, ReadUInt16LittleEndian(content, 28) & 0x3FFF);
			}

			//Lossless: VP8L packs two 14-bit dimensions, each stored one less than its value, into the
			//four bytes after its one-byte signature.
			if (HasAsciiTag(content, 12, "VP8L"))
			{
				var packed = (uint)(content[21] | (content[22] << 8) | (content[23] << 16) | (content[24] << 24));
				return Bound((packed & 0x3FFF) + 1, ((packed >> 14) & 0x3FFF) + 1);
			}

			//Extended: VP8X states the canvas size directly as two 24-bit values, each stored one less
			//than its value.
			if (HasAsciiTag(content, 12, "VP8X"))
			{
				var canvasWidth = (long)(content[24] | (content[25] << 8) | (content[26] << 16)) + 1;
				var canvasHeight = (long)(content[27] | (content[28] << 8) | (content[29] << 16)) + 1;
				return Bound(canvasWidth, canvasHeight);
			}

			return null;
		}

		private static (int Width, int Height)? ReadIcoDimensions(byte[] content)
		{
			//An .ico is a DIRECTORY of images at different sizes, not one image, so "the dimensions" has to
			//be a choice rather than a read. The LARGEST entry is reported, because that is the intrinsic
			//size a browser resolves the file to when nothing constrains it and the value a consumer of the
			//stored width and height would expect. Reporting the first entry instead would report whichever
			//size the producing tool happened to emit first - conventionally the 16x16 one - and would
			//understate every multi-resolution icon.
			if (content.Length < 6)
			{
				return null;
			}

			var entryCount = ReadUInt16LittleEndian(content, 4);
			long bestWidth = 0;
			long bestHeight = 0;
			for (var entry = 0; entry < entryCount; entry++)
			{
				//Each directory entry is sixteen bytes and opens with the width and the height, each a
				//single byte in which zero means 256.
				var entryOffset = 6 + ((long)entry * 16);
				if (entryOffset + 16 > content.Length)
				{
					break;
				}

				var entryWidth = content[entryOffset] == 0 ? 256 : content[entryOffset];
				var entryHeight = content[entryOffset + 1] == 0 ? 256 : content[entryOffset + 1];
				if (entryWidth * entryHeight > bestWidth * bestHeight)
				{
					bestWidth = entryWidth;
					bestHeight = entryHeight;
				}
			}

			return Bound(bestWidth, bestHeight);
		}

		private static (int Width, int Height)? ReadTiffDimensions(byte[] content, bool isBigEndian)
		{
			var limit = Math.Min(content.Length, MAX_IMAGE_HEADER_PROBE_BYTES);
			if (limit < 8)
			{
				return null;
			}

			var directoryOffset = isBigEndian
				? ReadInt32BigEndian(content, 4)
				: (long)(uint)ReadInt32LittleEndian(content, 4);

			//The directory has to sit after the header and inside the probe window, with room for its own
			//entry count.
			if (directoryOffset < 8 || directoryOffset + 2 > limit)
			{
				return null;
			}

			var entryCount = isBigEndian
				? ReadUInt16BigEndian(content, (int)directoryOffset)
				: ReadUInt16LittleEndian(content, (int)directoryOffset);

			long? width = null;
			long? height = null;
			for (var entry = 0; entry < entryCount; entry++)
			{
				//Each directory entry is twelve bytes: a two-byte tag, a two-byte field type, a four-byte
				//count and a four-byte value.
				var entryOffset = directoryOffset + 2 + ((long)entry * 12);
				if (entryOffset + 12 > limit)
				{
					break;
				}

				var tag = isBigEndian
					? ReadUInt16BigEndian(content, (int)entryOffset)
					: ReadUInt16LittleEndian(content, (int)entryOffset);
				if (tag != 0x0100 && tag != 0x0101)
				{
					continue;
				}

				var fieldType = isBigEndian
					? ReadUInt16BigEndian(content, (int)entryOffset + 2)
					: ReadUInt16LittleEndian(content, (int)entryOffset + 2);

				//Field type 3 is a 16-bit value, left-aligned in the four-byte value field; type 4 is a
				//32-bit value. Anything else is not a dimension this reader will interpret.
				long value;
				if (fieldType == 3)
				{
					value = isBigEndian
						? ReadUInt16BigEndian(content, (int)entryOffset + 8)
						: ReadUInt16LittleEndian(content, (int)entryOffset + 8);
				}
				else if (fieldType == 4)
				{
					value = isBigEndian
						? ReadInt32BigEndian(content, (int)entryOffset + 8)
						: (long)(uint)ReadInt32LittleEndian(content, (int)entryOffset + 8);
				}
				else
				{
					continue;
				}

				if (tag == 0x0100)
				{
					width = value;
				}
				else
				{
					height = value;
				}

				if (width.HasValue && height.HasValue)
				{
					break;
				}
			}

			if (!width.HasValue || !height.HasValue)
			{
				return null;
			}

			return Bound(width.Value, height.Value);
		}

		private static (int Width, int Height)? ReadJpegDimensions(byte[] content)
		{
			var limit = Math.Min(content.Length, MAX_IMAGE_HEADER_PROBE_BYTES);

			//Skip the two-byte start-of-image marker and walk the marker stream.
			var offset = 2;
			while (offset + 3 < limit)
			{
				//Markers are introduced by one or more 0xFF fill bytes.
				if (content[offset] != 0xFF)
				{
					offset++;
					continue;
				}

				var marker = content[offset + 1];

				//Standalone markers carry no length: fill bytes, the restart markers and the two
				//image-delimiting markers.
				if (marker == 0xFF || marker == 0x01 || (marker >= 0xD0 && marker <= 0xD9))
				{
					offset += 2;
					continue;
				}

				var segmentLength = ReadUInt16BigEndian(content, offset + 2);
				if (segmentLength < 2)
				{
					return null;
				}

				//Every start-of-frame marker states the frame dimensions in the same place. 0xC4, 0xC8 and
				//0xCC fall inside the numeric range but are not frame headers, so they are excluded.
				var isStartOfFrame = marker >= 0xC0 && marker <= 0xCF && marker != 0xC4 && marker != 0xC8 && marker != 0xCC;
				if (isStartOfFrame)
				{
					if (offset + 9 >= limit)
					{
						return null;
					}

					//Within the frame header: one byte of sample precision, then height, then width.
					return Bound(ReadUInt16BigEndian(content, offset + 7), ReadUInt16BigEndian(content, offset + 5));
				}

				//Start of scan means the compressed data has begun and no frame header follows it.
				if (marker == 0xDA)
				{
					return null;
				}

				offset += 2 + (int)segmentLength;
			}

			return null;
		}

	}
}
