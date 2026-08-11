using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace WebVella.Erp.Web.Models
{
	public class Theme
	{
		[JsonProperty("id")]
		public Guid Id { get; set; } = Guid.Empty;

		[JsonProperty("label")]
		public string Label { get; set; } = "Default";

		[JsonProperty("name")]
		public string Name { get; set; } = "default";

		[JsonProperty("description")]
		public string Description { get; set; } = "this is the default theme of the application";

		[JsonProperty("brand_logo")]
		public string BrandLogo { get; set; } = "/_content/WebVella.Erp.Web/assets/logo.png";

		[JsonProperty("brand_logo_text")]
		public string BrandLogoText { get; set; } = "/_content/WebVella.Erp.Web/assets/logo-text.png";

		[JsonProperty("brand_favicon")]
		public string BrandFavIcon { get; set; } = "/_content/WebVella.Erp.Web/assets/favicon.png";

		[JsonProperty("brand_color")]
		public string BrandColor { get; set; } = "#fff";

		[JsonProperty("brand_url")]
		public string BrandUrl { get; set; } = "/";

		[JsonProperty("brand_background_color")]
		public string BrandBackgroundColor { get; set; } = "#192637";

		[JsonProperty("brand_inner_background_gradient")]
		public string BrandInnerBackgroundGradient { get; set; } = "linear-gradient(to bottom,rgba(255,255,255,0.20) 0%, rgba(255,255,255,0.075) 15px,rgba(255,255,255,0) 100%)";

		[JsonProperty("brand_aux_color")]
		public string BrandAuxilaryColor { get; set; } = "#FF9800";

		[JsonProperty("brand_hover_color")]
		public string BrandHoverColor { get; set; } = "rgba(255,255,255,0.15)";

		[JsonProperty("page_background_color")]
		public string PageBackgroundColor { get; set; } = "#fff";

		[JsonProperty("page_background_image")]
		public string PageBackgroundImage { get; set; } = "";

		[JsonProperty("header_background_color")]
		public string HeaderBackgroundColor { get; set; } = "#fff";

		[JsonProperty("body_font_family")]
		public string BodyFontFamily { get; set; } = "Roboto";

		[JsonProperty("body_font_url")]
		public string BodyFontUrl { get; set; } = "/_content/WebVella.Erp.Web/css/Roboto/Roboto-Regular.ttf";

		[JsonProperty("body_font_size")]
		public string BodyFontSize { get; set; } = "14px";

		[JsonProperty("body_font_color")]
		public string BodyFontColor { get; set; } = "#333";

		[JsonProperty("headings_font_family")]
		public string HeadingsFontFamily { get; set; } = "";

		[JsonProperty("headings_font_url")]
		public string HeadingsFontUrl { get; set; } = "";

		[JsonProperty("headings_font_color")]
		public string HeadingsFontColor { get; set; } = "";

		[JsonProperty("gray_border_color")]
		public string GrayBorderColor { get; set; } = "#e1e4e8";


		//Primary
		[JsonProperty("primary_color")]
		public string PrimaryColor { get; set; } = "#007bff";

		//Secondary
		[JsonProperty("secondary_color")]
		public string SecondaryColor { get; set; } = "#6c757d";

		//Success
		[JsonProperty("success_color")]
		public string SuccessColor { get; set; } = "#28a745";

		//Danger
		[JsonProperty("danger_color")]
		public string DangerColor { get; set; } = "#dc3545";

		//Warning
		[JsonProperty("warning_color")]
		public string WarningColor { get; set; } = "#ffc107";

		//Info
		[JsonProperty("info_color")]
		public string InfoColor { get; set; } = "#17a2b8";

		//Light
		[JsonProperty("light_color")]
		public string LightColor { get; set; } = "#f8f9fa";
		
		//Dark
		[JsonProperty("dark_color")]
		public string DarkColor { get; set; } = "#343a40";



		//Red
		// P6-11 (WCAG 2.1 AA 1.4.3 Contrast Minimum). THREAT ADDRESSED: this token was Material Red
		// 500 (#F44336), measured at runtime as 3.68:1 against the white page background - below the
		// 4.5:1 minimum for normal-size text. Three elements on the Projects dashboard render through
		// it (`.go-red`: an overdue-task count and two overdue dates). Raised one step on the same
		// Material ramp to Red 700, which measures 4.98:1.
		// KNOWN RIPPLES, established by re-measuring at runtime rather than by assumption:
		//  - `.toast.toast-error` uses this token as a BACKGROUND behind white text, whose ratio
		//    improves from 3.28:1 to 4.21:1.
		//  - `.go-red` is ALSO used as text inside the SDK Web API page's #212121 request blocks,
		//    where darkening made it worse (4.37:1 -> 3.23:1). That is corrected by the scoped
		//    `.go-white .go-red` rule in Theme/styles.css, which measures 5.39:1 on #212121.
		//  - The Tasks and Task-Priority doughnut series read one Material step darker. The TASKS
		//    widget's legend tracks the arcs exactly, because its legend values are `.go-red` and
		//    resolve through this same token (verified: legend rgb(211,47,47) == arc #D32F2F).
		//    The TASK-PRIORITY widget's legend does NOT track, and an earlier revision of this
		//    comment wrongly claimed it did. Its arcs read this token
		//    (PcProjectWidgetTasksPriorityChart.cs:119-120) but its legend renders
		//    `style="color: @option.Color"` from the PERSISTED SelectOption.Color, seeded #F44336 in
		//    WebVella.Erp.Plugins.Next/NextPlugin.20190203.cs. Those two values were only ever
		//    coincidentally equal - any operator recolouring a priority option has always broken the
		//    agreement - so this exposes a pre-existing coupling rather than creating one. The
		//    residue is exactly 128 pixels across two 12x12 icons, one Material step apart in the
		//    same hue; reverting a measured 3.68:1 text failure to remove that is the wrong trade.
		//    Recorded in docs/security/risk-register.md.
		//  - `.go-bkg-red` is referenced by no view in the repository.
		// NOT EXTENDED TO THE REST OF THE PALETTE - see the "Semantic colour palette" entry in
		// docs/security/risk-register.md. The `.go-*` family is a Material FILL palette reused for
		// text. `.go-green` measures 2.78:1 on white and Green's ramp does reach compliance at
		// Green 800 (4.97:1), but Orange's does NOT at any step (500 = 2.16:1, 700 = 3.05:1,
		// 800 and 900 = 3.79:1), so a per-hue darkening cannot make the family compliant; it would
		// also add a second instance of the Task-Priority legend divergence above. The remedy is a
		// text-specific variant set, which is the feature addition the delivery contract excludes.
		// WCAG 1.4.1 Use of Colour is met either way: every coloured value in these widgets is
		// paired with a monochrome label.
		[JsonProperty("red_color")]
		public string RedColor { get; set; } = "#D32F2F";

		[JsonProperty("red_light_color")]
		public string RedLightColor { get; set; } = "#FFEBEE";

		[JsonProperty("red_dark_color")]
		public string RedDarkColor { get; set; } = "#B71C1C";

		//Pink
		[JsonProperty("pink_color")]
		public string PinkColor { get; set; } = "#E91E63";

		[JsonProperty("pink_light_color")]
		public string PinkLightColor { get; set; } = "#FCE4EC";

		[JsonProperty("pink_dark_color")]
		public string PinkDarkColor { get; set; } = "#880E4F";

		//Purple
		[JsonProperty("purple_color")]
		public string PurpleColor { get; set; } = "#9C27B0";

		[JsonProperty("purple_light_color")]
		public string PurpleLightColor { get; set; } = "#F3E5F5";

		[JsonProperty("purple_dark_color")]
		public string PurpleDarkColor { get; set; } = "#4A148C";

		//Deep purple
		[JsonProperty("deep_purple_color")]
		public string DeepPurpleColor { get; set; } = "#673AB7";

		[JsonProperty("deep_purple_light_color")]
		public string DeepPurpleLightColor { get; set; } = "#EDE7F6";

		[JsonProperty("deep_purple_dark_color")]
		public string DeepPurpleDarkColor { get; set; } = "#311B92";

		//Indigo
		[JsonProperty("indigo_color")]
		public string IndigoColor { get; set; } = "#3F51B5";

		[JsonProperty("indigo_light_color")]
		public string IndigoLightColor { get; set; } = "#E8EAF6";

		[JsonProperty("indigo_dark_color")]
		public string IndigoDarkColor { get; set; } = "#1A237E";

		//Blue
		[JsonProperty("blue_color")]
		public string BlueColor { get; set; } = "#2196F3";

		[JsonProperty("blue_light_color")]
		public string BlueLightColor { get; set; } = "#E3F2FD";

		[JsonProperty("blue_dark_color")]
		public string BlueDarkColor { get; set; } = "#0D47A1";

		//Light Blue
		[JsonProperty("light_blue_color")]
		public string LightBlueColor { get; set; } = "#03A9F4";

		[JsonProperty("light_blue_light_color")]
		public string LightBlueLightColor { get; set; } = "#E1F5FE";

		[JsonProperty("light_blue_dark_color")]
		public string LightBlueDarkColor { get; set; } = "#01579B";

		//Cyan
		[JsonProperty("cyan_color")]
		public string CyanColor { get; set; } = "#00BCD4";

		[JsonProperty("cyan_light_color")]
		public string CyanLightColor { get; set; } = "#E0F7FA";

		[JsonProperty("cyan_dark_color")]
		public string CyanDarkColor { get; set; } = "#006064";

		//Teal
		[JsonProperty("teal_color")]
		public string TealColor { get; set; } = "#009688";

		[JsonProperty("teal_light_color")]
		public string TealLightColor { get; set; } = "#E0F2F1";

		[JsonProperty("teal_dark_color")]
		public string TealDarkColor { get; set; } = "#004D40";

		//Green
		[JsonProperty("green_color")]
		public string GreenColor { get; set; } = "#4CAF50";

		[JsonProperty("green_light_color")]
		public string GreenLightColor { get; set; } = "#E8F5E9";

		[JsonProperty("green_dark_color")]
		public string GreenDarkColor { get; set; } = "#1B5E20";

		//Light Green
		[JsonProperty("light_green_color")]
		public string LightGreenColor { get; set; } = "#8BC34A";

		[JsonProperty("light_green_light_color")]
		public string LightGreenLightColor { get; set; } = "#F1F8E9";

		[JsonProperty("light_green_dark_color")]
		public string LightGreenDarkColor { get; set; } = "#33691E";

		//Lime
		[JsonProperty("lime_color")]
		public string LimeColor { get; set; } = "#CDDC39";

		[JsonProperty("lime_light_color")]
		public string LimeLightColor { get; set; } = "#F9FBE7";

		[JsonProperty("lime_dark_color")]
		public string limeDarkColor { get; set; } = "#827717";

		//Yellow
		[JsonProperty("yellow_color")]
		public string YellowColor { get; set; } = "#FFEB3B";

		[JsonProperty("yellow_light_color")]
		public string YellowLightColor { get; set; } = "#FFFDE7";

		[JsonProperty("yellow_dark_color")]
		public string YellowDarkColor { get; set; } = "#F57F17";

		//Amber
		[JsonProperty("amber_color")]
		public string AmberColor { get; set; } = "#FFC107";

		[JsonProperty("amber_light_color")]
		public string AmberLightColor { get; set; } = "#FFF8E1";

		[JsonProperty("amber_dark_color")]
		public string AmberDarkColor { get; set; } = "#FF6F00";


		//Orange
		[JsonProperty("orange_color")]
		public string OrangeColor { get; set; } = "#FF9800";

		[JsonProperty("orange_light_color")]
		public string OrangeLightColor { get; set; } = "#FFF3E0";

		[JsonProperty("orange_dark_color")]
		public string OrangeDarkColor { get; set; } = "#E65100";

		//Deep Orange
		[JsonProperty("deep_orange_color")]
		public string DeepOrangeColor { get; set; } = "#FF5722";

		[JsonProperty("deep_orange_light_color")]
		public string DeepOrangeLightColor { get; set; } = "#FBE9E7";

		[JsonProperty("deep_orange_dark_color")]
		public string DeepOrangeDarkColor { get; set; } = "#BF360C";


		//Brown
		[JsonProperty("brown_color")]
		public string BrownColor { get; set; } = "#795548";

		[JsonProperty("brown_light_color")]
		public string BrownLightColor { get; set; } = "#EFEBE9";

		[JsonProperty("brown_dark_color")]
		public string BrownDarkColor { get; set; } = "#3E2723";

		//Gray
		// P6-11 (WCAG 2.1 AA 1.4.3 Contrast Minimum). THREAT ADDRESSED: this token was Material Grey
		// 500 (#9E9E9E), which measures 2.68:1 against the white page background - far below the
		// 4.5:1 minimum for normal-size text, and the worst-scoring and highest-volume contrast
		// failure measured at runtime (18 elements across the Projects dashboard and the SDK data
		// source list, all rendered through `.go-gray` / `.go-grey`). Raised one step on the same
		// Material ramp to Grey 600, which measures 4.61:1. The token, not the call sites, is changed
		// because `--gray_color` is consumed by six declarations in styles.css and every one of them
		// benefits: three are text (`.go-gray`, `#nav .nav-caret`, `#nav .dropdown-header`), one is an
		// SVG fill, one is a decorative bullet glyph, and `.go-bkg-gray` is referenced by no view in
		// the repository. No consumer relies on the lighter value.
		[JsonProperty("gray_color")]
		public string GrayColor { get; set; } = "#757575";

		[JsonProperty("gray_light_color")]
		public string GrayLightColor { get; set; } = "#FAFAFA";

		[JsonProperty("gray_semi_light_color")]
		public string GraySemiLightColor { get; set; } = "#ccc";

		[JsonProperty("gray_dark_color")]
		public string GrayDarkColor { get; set; } = "#212121";

		//Blue Gray
		[JsonProperty("blue_gray_color")]
		public string BlueGrayColor { get; set; } = "#607D8B";

		[JsonProperty("blue_gray_light_color")]
		public string BlueGrayLightColor { get; set; } = "#ECEFF1";

		[JsonProperty("blue_gray_dark_color")]
		public string BlueGrayDarkColor { get; set; } = "#263238";

		//White
		[JsonProperty("white_color")]
		public string WhiteColor { get; set; } = "#FFFFFF";

		//Black
		[JsonProperty("black_color")]
		public string BlackColor { get; set; } = "#000000";
	}
}
